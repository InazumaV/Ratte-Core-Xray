package common

func BuildSlice[s, t any](source []s, handle func(v s) t) (p []t) {
	p = make([]t, 0, len(source))
	for i := range source {
		p = append(p, handle(source[i]))
	}
	return
}

func InSlice[T comparable](slice []T, value T) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}
