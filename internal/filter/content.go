package filter

import (
	"regexp"
	"strings"
)

var reContent = regexp.MustCompile(`(post|blog)s?|docs|support/|/(\d{4}|pages?)/\d+/`)

// RemoveContentFilter - фильтр: удаляет URL похожие на контент (блоги, посты)
type RemoveContentFilter struct {
	contentPrefixes []string
}

func (f *RemoveContentFilter) Name() string { return "removecontent" }

func (f *RemoveContentFilter) Apply(path string, params map[string]string, meta *Meta) bool {
	// Проверяем количество дефисов в каждой части пути
	for _, part := range strings.Split(path, "/") {
		if strings.Count(part, "-") > 3 {
			return false // Похоже на контент (slug статьи)
		}
	}

	// Проверяем кэшированные префиксы контента
	for _, prefix := range f.contentPrefixes {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}

	// Проверяем regex паттерн контента
	match := reContent.FindStringIndex(path)
	if match != nil {
		// Кэшируем новый префикс
		f.contentPrefixes = append(f.contentPrefixes, path[:match[1]])
	}

	return true
}

// Reset сбрасывает кэш префиксов контента
func (f *RemoveContentFilter) Reset() {
	f.contentPrefixes = nil
}
