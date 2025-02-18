package dispatcher

import "github.com/InazumaV/Ratte-Core-Xray/limiter"

func (d *DefaultDispatcher) AddLimiter(nodeName string, l *limiter.Limiter) error {
	d.ls.Set(nodeName, l)
	return nil
}

func (d *DefaultDispatcher) RemoveLimiter(nodeName string) error {
	d.ls.Remove(nodeName)
	return nil
}
