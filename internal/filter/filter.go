package filter

// Meta содержит метаданные для фильтров
type Meta struct {
	Strict     bool
	ExtList    []string
	VulnParams map[string]struct{}
}

// Filter - интерфейс для всех фильтров
// Apply возвращает true если URL должен быть сохранён
type Filter interface {
	Name() string
	Apply(path string, params map[string]string, meta *Meta) bool
}

// Registry хранит все доступные фильтры
type Registry struct {
	filters map[string]Filter
}

// NewRegistry создаёт новый реестр фильтров
func NewRegistry() *Registry {
	r := &Registry{
		filters: make(map[string]Filter),
	}

	// Регистрируем все фильтры
	r.Register(&HasExtFilter{})
	r.Register(&NoExtFilter{})
	r.Register(&HasParamsFilter{})
	r.Register(&NoParamsFilter{})
	r.Register(&WhitelistFilter{})
	r.Register(&BlacklistFilter{})
	r.Register(&RemoveContentFilter{})
	r.Register(&VulnParamFilter{})

	return r
}

// Register добавляет фильтр в реестр
func (r *Registry) Register(f Filter) {
	r.filters[f.Name()] = f
}

// Get возвращает фильтр по имени
func (r *Registry) Get(name string) (Filter, bool) {
	f, ok := r.filters[name]
	return f, ok
}

// Has проверяет наличие фильтра
func (r *Registry) Has(name string) bool {
	_, ok := r.filters[name]
	return ok
}

// NormalizeFilterName нормализует имя фильтра (обрабатывает вариации)
func NormalizeFilterName(name string) string {
	switch name {
	case "hasparam":
		return "hasparams"
	case "noparam":
		return "noparams"
	case "hasexts":
		return "hasext"
	case "noexts":
		return "noext"
	default:
		return name
	}
}
