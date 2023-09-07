package session

import (
	"log"
	"net"
	"testing"
	"time"
)

func TestSessionNoEvict(t *testing.T) {
	sc := New(2)
	ip1 := net.ParseIP("10.10.10.10")
	ip2 := net.ParseIP("20.20.20.20")
	queryKey := SessionKey{
		SrcIP:   ip1.String(),
		DstIP:   ip2.String(),
		SrcPort: 56789,
		DstPort: 53,
		TransID: 45678,
	}

	queryValue := SessionValue{
		QueryTime: time.Now(),
		Domain:    "www.test.com",
	}

	sc.Add(queryKey, queryValue)
	v, ok := sc.Find(queryKey)
	if !ok {
		log.Fatalf("should find but not find")
	}
	log.Printf("find value %v", v)

	ip3 := net.ParseIP("30.30.30.30")
	queryKey2 := SessionKey{
		SrcIP:   ip3.String(),
		DstIP:   ip2.String(),
		SrcPort: 56789,
		DstPort: 53,
		TransID: 45678,
	}

	if _, ok := sc.Find(queryKey2); ok {
		log.Fatalf("should not find but find")
	}

	sc.Delete(queryKey)
	if _, ok := sc.Find(queryKey); ok {
		log.Fatalf("should not find but find")
	}
}

func TestSessionWithEvict(t *testing.T) {
	sc := New(2)
	ip1 := net.ParseIP("10.10.10.10")
	ip2 := net.ParseIP("20.20.20.20")
	queryKey := SessionKey{
		SrcIP:   ip1.String(),
		DstIP:   ip2.String(),
		SrcPort: 56789,
		DstPort: 53,
		TransID: 45678,
	}

	queryValue := SessionValue{
		QueryTime: time.Now(),
		Domain:    "www.test.com",
	}

	sc.Add(queryKey, queryValue)

	ip3 := net.ParseIP("30.30.30.30")
	queryKey2 := SessionKey{
		SrcIP:   ip3.String(),
		DstIP:   ip2.String(),
		SrcPort: 56789,
		DstPort: 53,
		TransID: 45678,
	}

	sc.Add(queryKey2, queryValue)

	ip4 := net.ParseIP("30.30.30.40")
	queryKey3 := SessionKey{
		SrcIP:   ip4.String(),
		DstIP:   ip2.String(),
		SrcPort: 56789,
		DstPort: 53,
		TransID: 45678,
	}

	log.Printf("current cache count %d", sc.c.Len())

	sc.Add(queryKey3, queryValue)
}
