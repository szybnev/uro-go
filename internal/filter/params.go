package filter

// HasParamsFilter - фильтр: только URL с параметрами
type HasParamsFilter struct{}

func (f *HasParamsFilter) Name() string { return "hasparams" }

func (f *HasParamsFilter) Apply(path string, params map[string]string, meta *Meta) bool {
	return len(params) > 0
}

// NoParamsFilter - фильтр: только URL без параметров
type NoParamsFilter struct{}

func (f *NoParamsFilter) Name() string { return "noparams" }

func (f *NoParamsFilter) Apply(path string, params map[string]string, meta *Meta) bool {
	return len(params) == 0
}

// VulnParamFilter - фильтр: только URL с потенциально уязвимыми параметрами
type VulnParamFilter struct{}

func (f *VulnParamFilter) Name() string { return "vuln" }

func (f *VulnParamFilter) Apply(path string, params map[string]string, meta *Meta) bool {
	for param := range params {
		if _, ok := meta.VulnParams[param]; ok {
			return true
		}
	}
	return false
}
