package config

// Config содержит конфигурацию из CLI аргументов
type Config struct {
	InputFile  string
	OutputFile string
	Whitelist  []string
	Blacklist  []string
	Filters    []string
	KeepSlash  bool
}

// GetExtList возвращает список расширений для фильтрации
func (c *Config) GetExtList() []string {
	if len(c.Whitelist) > 0 {
		return c.Whitelist
	}
	if len(c.Blacklist) > 0 {
		return c.Blacklist
	}
	return DefaultBlacklist
}

// IsWhitelistMode возвращает true если используется whitelist режим
func (c *Config) IsWhitelistMode() bool {
	return len(c.Whitelist) > 0
}

// HasFilter проверяет наличие фильтра в списке
func (c *Config) HasFilter(name string) bool {
	for _, f := range c.Filters {
		if f == name {
			return true
		}
	}
	return false
}
