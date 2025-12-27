package filter

import (
	"github.com/szybnev/uro-go/pkg/urlutil"
)

// checkExt проверяет наличие расширения и совпадение со списком
func checkExt(path string, extList []string) (hasExt bool, inList bool) {
	ext := urlutil.GetExtension(path)
	if ext == "" {
		return false, false
	}

	for _, e := range extList {
		if ext == e {
			return true, true
		}
	}
	return true, false
}

// HasExtFilter - фильтр: только URL с расширением
type HasExtFilter struct{}

func (f *HasExtFilter) Name() string { return "hasext" }

func (f *HasExtFilter) Apply(path string, params map[string]string, meta *Meta) bool {
	return urlutil.HasExtension(path)
}

// NoExtFilter - фильтр: только URL без расширения
type NoExtFilter struct{}

func (f *NoExtFilter) Name() string { return "noext" }

func (f *NoExtFilter) Apply(path string, params map[string]string, meta *Meta) bool {
	return !urlutil.HasExtension(path)
}

// WhitelistFilter - фильтр: только разрешённые расширения или без расширения
type WhitelistFilter struct{}

func (f *WhitelistFilter) Name() string { return "whitelist" }

func (f *WhitelistFilter) Apply(path string, params map[string]string, meta *Meta) bool {
	hasExt, inList := checkExt(path, meta.ExtList)
	// Если расширение в whitelist - OK
	// Если нет расширения и не strict режим - тоже OK
	return inList || (!meta.Strict && !hasExt)
}

// BlacklistFilter - фильтр: исключить запрещённые расширения
type BlacklistFilter struct{}

func (f *BlacklistFilter) Name() string { return "blacklist" }

func (f *BlacklistFilter) Apply(path string, params map[string]string, meta *Meta) bool {
	hasExt, inList := checkExt(path, meta.ExtList)
	// Если расширение НЕ в blacklist - OK
	// Если нет расширения и не strict режим - тоже OK
	return !inList || (!meta.Strict && !hasExt)
}
