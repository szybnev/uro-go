package processor

import (
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/szybnev/uro-go/internal/config"
	"github.com/szybnev/uro-go/internal/filter"
	"github.com/szybnev/uro-go/pkg/urlutil"
)

var reInt = regexp.MustCompile(`/\d+([?/]|$)`)

// URLProcessor обрабатывает и дедуплицирует URL
type URLProcessor struct {
	config        *config.Config
	urlMap        map[string]map[string][]map[string]string // host → path → []params
	paramsSeen    map[string]struct{}                       // глобально виденные параметры
	patternsSeen  map[string]struct{}                       // виденные паттерны числовых путей
	activeFilters []filter.Filter
	filterMeta    *filter.Meta
	registry      *filter.Registry
}

// New создаёт новый URLProcessor
func New(cfg *config.Config) (*URLProcessor, error) {
	p := &URLProcessor{
		config:       cfg,
		urlMap:       make(map[string]map[string][]map[string]string),
		paramsSeen:   make(map[string]struct{}),
		patternsSeen: make(map[string]struct{}),
		registry:     filter.NewRegistry(),
	}

	if err := p.setupFilters(); err != nil {
		return nil, err
	}

	return p, nil
}

// setupFilters настраивает активные фильтры на основе конфигурации
func (p *URLProcessor) setupFilters() error {
	activeNames := []string{}

	// Нормализуем фильтры из конфигурации
	filters := urlutil.CleanArgs(p.config.Filters)

	// Проверяем keepcontent
	keepContent := false
	for _, f := range filters {
		if f == "keepcontent" {
			keepContent = true
		}
	}

	// Добавляем removecontent по умолчанию (если не keepcontent)
	if !keepContent {
		activeNames = append(activeNames, "removecontent")
	}

	// Проверяем allexts
	allExts := false
	for _, f := range filters {
		if f == "allexts" {
			allExts = true
		}
	}

	// Добавляем whitelist или blacklist (если не allexts)
	if !allExts {
		if p.config.IsWhitelistMode() {
			activeNames = append(activeNames, "whitelist")
		} else {
			activeNames = append(activeNames, "blacklist")
		}
	}

	// Добавляем пользовательские фильтры
	for _, f := range filters {
		if f == "keepcontent" || f == "keepslash" || f == "allexts" {
			continue // Эти обрабатываются отдельно
		}

		normalized := filter.NormalizeFilterName(f)
		if p.registry.Has(normalized) {
			activeNames = append(activeNames, normalized)
		} else {
			return fmt.Errorf("invalid filter: %s", f)
		}
	}

	// Собираем активные фильтры
	for _, name := range activeNames {
		if f, ok := p.registry.Get(name); ok {
			p.activeFilters = append(p.activeFilters, f)
		}
	}

	// Настраиваем метаданные для фильтров
	// ИСПРАВЛЕННЫЙ БАГ: strict = true только если hasext или noext явно указаны
	strict := false
	for _, f := range filters {
		if f == "hasext" || f == "noext" {
			strict = true
			break
		}
	}

	p.filterMeta = &filter.Meta{
		Strict:     strict,
		ExtList:    p.config.GetExtList(),
		VulnParams: config.VulnParams,
	}

	return nil
}

// ProcessLine обрабатывает одну строку входных данных
func (p *URLProcessor) ProcessLine(line string) {
	// Нормализуем строку
	line = urlutil.SanitizeUTF8(line)
	line = urlutil.NormalizePath(line, p.config.KeepSlash)

	if line == "" {
		return
	}

	// Парсим URL
	u, err := urlutil.ParseURL(line)
	if err != nil || u.Host == "" {
		return
	}

	p.processURL(u)
}

// processURL обрабатывает распарсенный URL
func (p *URLProcessor) processURL(u *url.URL) {
	host := urlutil.BuildHost(u)
	path := u.Path
	params := urlutil.ParamsToMap(u.RawQuery)

	// Определяем новые параметры
	newParams := make([]string, 0)
	for param := range params {
		if _, seen := p.paramsSeen[param]; !seen {
			newParams = append(newParams, param)
		}
	}

	// Применяем фильтры
	if !p.applyFilters(path, params) {
		return
	}

	// Обновляем глобально виденные параметры
	for _, param := range newParams {
		p.paramsSeen[param] = struct{}{}
	}

	// Инициализируем map для хоста если нужно
	if _, ok := p.urlMap[host]; !ok {
		p.urlMap[host] = make(map[string][]map[string]string)
	}

	// Проверяем, новый ли это путь
	_, pathExists := p.urlMap[host][path]

	if !pathExists {
		// Проверяем числовой паттерн
		if reInt.MatchString(path) {
			pattern := p.createPattern(path)
			if _, seen := p.patternsSeen[pattern]; seen {
				return // Паттерн уже видели
			}
			p.patternsSeen[pattern] = struct{}{}
		}

		// Добавляем новый путь
		p.urlMap[host][path] = []map[string]string{}
		if len(params) > 0 {
			p.urlMap[host][path] = append(p.urlMap[host][path], params)
		}
	} else {
		// Путь уже существует, проверяем параметры
		if len(newParams) > 0 {
			// Есть новые глобальные параметры
			p.urlMap[host][path] = append(p.urlMap[host][path], params)
		} else if len(params) > 0 && urlutil.CompareParams(p.urlMap[host][path], params) {
			// Есть новые параметры для этого пути
			p.urlMap[host][path] = append(p.urlMap[host][path], params)
		}
	}
}

// applyFilters применяет все активные фильтры к URL
func (p *URLProcessor) applyFilters(path string, params map[string]string) bool {
	for _, f := range p.activeFilters {
		if !f.Apply(path, params, p.filterMeta) {
			return false
		}
	}
	return true
}

// createPattern создаёт паттерн для пути с числами
func (p *URLProcessor) createPattern(path string) string {
	parts := strings.Split(path, "/")
	newParts := make([]string, 0, len(parts))
	lastIndex := 0

	for i, part := range parts {
		if isDigit(part) {
			lastIndex = i
			newParts = append(newParts, `\d+`)
		} else {
			newParts = append(newParts, regexp.QuoteMeta(part))
		}
	}

	// Берём только до последнего числа включительно
	return strings.Join(newParts[:lastIndex+1], "/")
}

// isDigit проверяет, состоит ли строка только из цифр
func isDigit(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Output записывает результаты в writer
func (p *URLProcessor) Output(w io.Writer) {
	for host, paths := range p.urlMap {
		for path, paramsList := range paths {
			if len(paramsList) > 0 {
				for _, params := range paramsList {
					fmt.Fprintln(w, host+path+urlutil.MapToQuery(params))
				}
			} else {
				fmt.Fprintln(w, host+path)
			}
		}
	}
}
