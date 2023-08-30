package analyzehandler

import (
	"encoding/json"
	"time"

	"github.com/hiwyw/dnscap-go/app/dnslog"
	"github.com/hiwyw/dnscap-go/app/logger"
)

const (
	delayLess10ms   = "0-10ms"
	delayLess100ms  = "10-100ms"
	delayLess1000ms = "100-1000ms"
	delayLess3000ms = "1000-3000ms"
	delayMore3000ms = "3000ms+"
)

func NewResult(interval time.Duration, ips, domains []string) *Result {
	ipCount := map[string]*CountResult{}
	for _, ip := range ips {
		ipCount[ip] = NewCountResult(false, false)
	}

	domainCount := map[string]*CountResult{}
	for _, domain := range domains {
		domainCount[domain] = NewCountResult(false, false)
	}

	r := &Result{
		ClientCount:         NewCountResult(true, true),
		RecursionCount:      NewCountResult(true, true),
		SpecialIpCounts:     ipCount,
		SpecialDomainCounts: domainCount,
	}
	return r
}

type Result struct {
	BeginTime           time.Time               `json:"begin_time"`
	EndTime             time.Time               `json:"end_time"`
	ClientCount         *CountResult            `json:"client_side"`
	RecursionCount      *CountResult            `json:"recursion_side"`
	SpecialIpCounts     map[string]*CountResult `json:"special_ips"`
	SpecialDomainCounts map[string]*CountResult `json:"special_domains"`
}

func (r *Result) count(dl *dnslog.Dnslog, isRecurseion bool) {
	if isRecurseion {
		r.RecursionCount.count(dl)
	} else {
		r.ClientCount.count(dl)
		r.countDomain(dl)
	}
	r.countIp(dl)
}

func (r *Result) countIp(dl *dnslog.Dnslog) {
	if len(r.SpecialIpCounts) == 0 {
		return
	}

	srcIp := dl.SrcIP.String()
	if _, ok := r.SpecialIpCounts[srcIp]; ok {
		r.SpecialIpCounts[srcIp].count(dl)
	}

	dstIp := dl.DstIP.String()
	if _, ok := r.SpecialIpCounts[dstIp]; ok {
		r.SpecialIpCounts[dstIp].count(dl)
	}
}

func (r *Result) countDomain(dl *dnslog.Dnslog) {
	if len(r.SpecialDomainCounts) == 0 {
		return
	}

	_, ok := r.SpecialDomainCounts[dl.Domain]
	if ok {
		r.SpecialDomainCounts[dl.Domain].count(dl)
	}
}

func (r *Result) Json() []byte {
	b, err := json.MarshalIndent(r, "", "    ")
	if err != nil {
		logger.Get().Errorf("analyze result marshal to json failed %s", err)
		return nil
	}
	return b
}

func NewCountResult(enableRcode, enableQtype bool) *CountResult {
	r := &CountResult{
		DelayCount: map[string]int{
			delayLess10ms:   0,
			delayLess100ms:  0,
			delayLess1000ms: 0,
			delayLess3000ms: 0,
			delayMore3000ms: 0,
		},
	}

	if enableRcode {
		r.RcodeCount = map[string]int{}
	}

	if enableQtype {
		r.QueryTypeCount = map[string]int{}
	}
	return r
}

type CountResult struct {
	QueryCount     int            `json:"query_count"`
	ResponseCount  int            `json:"response_count"`
	DelayCount     map[string]int `json:"delay_statistics"`
	RcodeCount     map[string]int `json:"rcode_statistics,omitempty"`
	QueryTypeCount map[string]int `json:"qtype_statistics,omitempty"`
}

func (c *CountResult) count(dl *dnslog.Dnslog) {
	if dl.Response {
		c.ResponseCount++
		c.countDelay(dl.ResolvDuration)
		c.countRcode(dl.Rcode)
		c.countQtype(dl.QueryType)
	} else {
		c.QueryCount++
	}
}

func (c *CountResult) countDelay(d time.Duration) {
	if d.Milliseconds() <= 10 {
		c.DelayCount[delayLess10ms]++
		return
	}

	if d.Milliseconds() > 10 && d.Milliseconds() <= 100 {
		c.DelayCount[delayLess100ms]++
		return
	}

	if d.Milliseconds() > 100 && d.Milliseconds() <= 1000 {
		c.DelayCount[delayLess1000ms]++
		return
	}

	if d.Milliseconds() > 1000 && int64(d) <= 3000 {
		c.DelayCount[delayLess3000ms]++
		return
	}

	if d.Milliseconds() > 3000 {
		c.DelayCount[delayMore3000ms]++
		return
	}
}

func (c *CountResult) countRcode(code string) {
	if c.RcodeCount == nil {
		return
	}

	_, ok := c.RcodeCount[code]
	if !ok {
		c.RcodeCount[code] = 1
	} else {
		c.RcodeCount[code]++
	}
}

func (c *CountResult) countQtype(t string) {
	if c.QueryTypeCount == nil {
		return
	}

	_, ok := c.QueryTypeCount[t]
	if !ok {
		c.QueryTypeCount[t] = 1
	} else {
		c.QueryTypeCount[t]++
	}
}
