package session

import (
	"time"

	lru "github.com/hashicorp/golang-lru"
)

func New(size int) *SessionCache {
	lruc, _ := lru.New(size)

	return &SessionCache{
		c: lruc,
	}
}

type SessionCache struct {
	c *lru.Cache
}

func (s *SessionCache) Add(k SessionKey, v SessionValue) (evicted bool) {
	evicted = s.c.Add(k, v)
	return
}

func (s *SessionCache) Delete(k SessionKey) {
	s.c.Remove(k)
}

func (s *SessionCache) Find(k SessionKey) (SessionValue, bool) {
	v, ok := s.c.Peek(k)
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
