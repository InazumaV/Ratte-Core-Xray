package common

func NewValue[T any](v T) *T {
	return &v
}
