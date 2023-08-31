package session

import (
	"time"

	lru "github.com/hashicorp/golang-lru"
)

const (
	slabNumber uint16 = 8
)

func New(size int) *SessionCache {
	s := &SessionCache{
		cache: []*lru.Cache{},
	}

	for i := 0; i < (int)(slabNumber); i++ {
		lc, _ := lru.New(size)
		s.cache = append(s.cache, lc)
	}
	return s
}

type SessionCache struct {
	cache []*lru.Cache
}

func (s *SessionCache) Add(k SessionKey, v SessionValue) (evicted bool) {
	evicted = s.cache[k.TransID&(slabNumber-1)].Add(k, v)
	return
}

func (s *SessionCache) Delete(k SessionKey) {
	s.cache[k.TransID&(slabNumber-1)].Remove(k)
}

func (s *SessionCache) FindWithRetry(k SessionKey, retries int) (SessionValue, bool) {
	for i := 0; i < retries; i++ {
		v, ok := s.Find(k)
		if ok {
			return v, ok
		}
		<-time.After(time.Millisecond)
	}
	return SessionValue{}, false
}

func (s *SessionCache) Find(k SessionKey) (SessionValue, bool) {
	v, ok := s.cache[k.TransID&(slabNumber-1)].Peek(k)
	if !ok {
		return SessionValue{}, false
	}
	return v.(SessionValue), true
}

type SessionKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	TransID uint16
}

type SessionValue struct {
	QueryTime time.Time
	QueryType string
	Domain    string
}
