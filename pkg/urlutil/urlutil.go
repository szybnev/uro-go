package urlutil

import (
	"net/url"
	"strings"
)

// ParamsToMap преобразует query string в map
func ParamsToMap(query string) map[string]string {
	result := make(map[string]string)
	if query == "" {
		return result
	}

	for _, pair := range strings.Split(query, "&") {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 && parts[0] != "" {
			result[parts[0]] = parts[1]
		} else if len(parts) == 1 && parts[0] != "" {
			result[parts[0]] = ""
		}
	}
	return result
}

// MapToQuery преобразует map параметров в query string
func MapToQuery(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}

	pairs := make([]string, 0, len(params))
	for k, v := range params {
		pairs = append(pairs, k+"="+v)
	}
	return "?" + strings.Join(pairs, "&")
}

// CompareParams проверяет, есть ли в new параметры, которых нет в existing
// Возвращает true если есть новые параметры
func CompareParams(existing []map[string]string, new map[string]string) bool {
	seen := make(map[string]struct{})
	for _, params := range existing {
		for key := range params {
			seen[key] = struct{}{}
		}
	}

	for key := range new {
		if _, ok := seen[key]; !ok {
			return true
		}
	}
	return false
}

// CleanArgs нормализует аргументы CLI (обрабатывает запятые и пробелы)
func CleanArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}

	result := make(map[string]struct{})

	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}

		// Разделяем по запятым
		if strings.Contains(arg, ",") {
			for _, part := range strings.Split(arg, ",") {
				part = strings.TrimSpace(strings.ToLower(part))
				if part != "" {
					result[part] = struct{}{}
				}
			}
		} else if strings.Contains(arg, " ") {
			// Разделяем по пробелам
			for _, part := range strings.Split(arg, " ") {
				part = strings.TrimSpace(strings.ToLower(part))
				if part != "" {
					result[part] = struct{}{}
				}
			}
		} else {
			result[strings.ToLower(arg)] = struct{}{}
		}
	}

	// Преобразуем set в slice
	output := make([]string, 0, len(result))
	for k := range result {
		output = append(output, k)
	}
	return output
}

// HasExtension проверяет, есть ли у пути расширение
func HasExtension(path string) bool {
	lastSlash := strings.LastIndex(path, "/")
	lastPart := path
	if lastSlash >= 0 {
		lastPart = path[lastSlash+1:]
	}
	return strings.Contains(lastPart, ".")
}

// GetExtension возвращает расширение из пути (без точки, в нижнем регистре)
func GetExtension(path string) string {
	lastSlash := strings.LastIndex(path, "/")
	lastPart := path
	if lastSlash >= 0 {
		lastPart = path[lastSlash+1:]
	}

	lastDot := strings.LastIndex(lastPart, ".")
	if lastDot < 0 {
		return ""
	}
	return strings.ToLower(lastPart[lastDot+1:])
}

// NormalizePath удаляет trailing slash если keepSlash=false
func NormalizePath(rawURL string, keepSlash bool) string {
	rawURL = strings.TrimSpace(rawURL)
	if !keepSlash {
		rawURL = strings.TrimSuffix(rawURL, "/")
	}
	return rawURL
}

// ParseURL парсит URL и возвращает его компоненты
func ParseURL(rawURL string) (*url.URL, error) {
	return url.Parse(rawURL)
}

// BuildHost возвращает scheme://host часть URL
func BuildHost(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

// SanitizeUTF8 удаляет невалидные UTF-8 последовательности
func SanitizeUTF8(s string) string {
	return strings.ToValidUTF8(s, "")
}
