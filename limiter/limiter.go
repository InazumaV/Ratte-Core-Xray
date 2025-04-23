package limiter

import (
	"github.com/InazumaV/Ratte-Core-Xray/common"
	"github.com/InazumaV/Ratte-Interface/params"
	cmap "github.com/orcaman/concurrent-map/v2"
	"golang.org/x/time/rate"
	"regexp"
	"sync"
)

type Limiter struct {
	IpLimit    int
	SpeedLimit uint64
	userLimit  cmap.ConcurrentMap[string, *UserLimit]
	userIpList cmap.ConcurrentMap[string, cmap.ConcurrentMap[string, struct{}]]
	ruleLock   sync.RWMutex
	RegexpRule []*regexp.Regexp
}

type UserLimit struct {
	UID        int
	IpLimit    int
	SpeedLimit uint64
}

func NewLimiter(ipLimit int, speedLimit uint64, rules []string) *Limiter {
	l := &Limiter{
		IpLimit:    ipLimit,
		SpeedLimit: speedLimit,
		userLimit:  cmap.ConcurrentMap[string, *UserLimit]{},
		userIpList: cmap.ConcurrentMap[string, cmap.ConcurrentMap[string, struct{}]]{},
	}
	l.UpdateRule(rules)
	return l
}

func (l *Limiter) AddUserInfos(us []params.UserInfo) {
	for _, u := range us {
		l.userLimit.Set(u.Name, &UserLimit{
			UID:        u.Id,
			IpLimit:    0, // need impl for user limit
			SpeedLimit: 0,
		})
	}
}

func (l *Limiter) DelUsers(nodeName string, us []string) {
	for _, u := range us {
		l.userIpList.Remove(common.FormatUserEmail(nodeName, u))
	}
}

func (l *Limiter) CheckIpLimitThenRecord(email string, ip string) (reject bool, err error) {
	info, ok := l.userLimit.Get(email)
	if !ok {
		return false, err
	}
	list, ok := l.userIpList.Get(email)
	if !ok {
		newList := cmap.ConcurrentMap[string, struct{}]{}
		newList.Set(ip, struct{}{})
		l.userIpList.Set(email, newList)
		return false, nil
	}
	_, ok = list.Get(ip)
	if !ok {
		return false, nil
	}
	if list.Count() > selectBigger(info.IpLimit, l.IpLimit) {
		return true, nil
	}
	list.Set(ip, struct{}{})
	return false, nil
}

func (l *Limiter) CheckIpByCount(email string, c int) bool {
	info, ok := l.userLimit.Get(email)
	if !ok {
		return false
	}
	if c >= info.IpLimit {
		return true
	}
	return false
}

func (l *Limiter) CheckSpeedLimitTheGetRateLimiter(email string) (limiter *rate.Limiter, err error) {
	info, ok := l.userLimit.Get(email)
	if !ok {
		return nil, err
	}
	sl := selectBigger(info.IpLimit, l.IpLimit)
	if sl == 0 {
		return nil, nil
	}
	li := rate.NewLimiter(rate.Limit(sl), sl)
	return li, nil
}

func (l *Limiter) CheckRule(contents ...string) (reject bool) {
	l.ruleLock.RLock()
	defer l.ruleLock.RUnlock()
	if len(contents) == 0 {
		return false
	}
	for _, rule := range l.RegexpRule {
		for _, content := range contents {
			if rule.MatchString(content) {
				return true
			}
		}
	}
	return false
}

func (l *Limiter) UpdateRule(rules []string) (reject bool) {
	ruleN := make([]*regexp.Regexp, 0, len(rules))
	for _, rule := range rules {
		ruleN = append(ruleN, regexp.MustCompile(rule))
	}
	l.ruleLock.Lock()
	defer l.ruleLock.Unlock()
	l.RegexpRule = ruleN
	return false
}
