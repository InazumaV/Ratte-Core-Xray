package common

func BuildSlice[s, t any](source []s, handle func(v s) t) (p []t) {
	p = make([]t, 0, len(source))
	for i := range source {
		p = append(p, handle(source[i]))
	}
	return
}
