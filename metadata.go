package service

type MD map[string]string

func Metadata() MD {
	return MD{}
}

func (m MD) Set(name, value string) {
	m[name] = value
}

func (m MD) Get(name string) (string, bool) {
	v, found := m[name]
	return v, found
}
