package analyzer

import (
	"time"

	"github.com/hiwyw/dnscap-go/app/logger"
	"github.com/hiwyw/dnscap-go/app/types"
	"github.com/natefinch/lumberjack"
)

const (
	taskChannelBuffer = 100
)

func New(filename string, interval time.Duration, ips, domains, selfIps []string) *Analyzer {
	ipsMap := map[string]struct{}{}
	for _, ip := range selfIps {
		ipsMap[ip] = struct{}{}
	}

	a := &Analyzer{
		selfIps: ipsMap,
		taskCh:  make(chan *types.Dnslog, taskChannelBuffer),
		outLogger: &lumberjack.Logger{
			Filename:   filename,
			MaxSize:    50,
			MaxBackups: 10,
			MaxAge:     100,
			Compress:   true,
		},
		ips:      ips,
		domains:  domains,
		interval: interval,
		result:   NewResult(interval, ips, domains),
		closeCh:  make(chan struct{}),
	}

	go a.taskLoop()

	return a
}

type Analyzer struct {
	begin     bool
	endTime   time.Time
	selfIps   map[string]struct{}
	ips       []string
	domains   []string
	interval  time.Duration
	taskCh    chan *types.Dnslog
	outLogger *lumberjack.Logger
	result    *Result
	closeCh   chan struct{}
}

func (a *Analyzer) Handle(dl *types.Dnslog) {
	a.taskCh <- dl
}

func (a *Analyzer) Stop() {
	close(a.taskCh)
	<-a.closeCh
}

func (a *Analyzer) taskLoop() {
	for {
		dl, ok := <-a.taskCh
		if !ok {
			a.out()
			a.closeCh <- struct{}{}
			logger.Infof("analyze handleer exitting")
			return
		}
		a.analyze(dl)
	}
}

func (a *Analyzer) analyze(dl *types.Dnslog) {
	if !a.begin {
		a.endTime = dl.PacketTime.Add(a.interval)
		a.begin = true
	}

	if dl.PacketTime.After(a.endTime) {
		a.out()
		a.endTime = a.endTime.Add(a.interval)
	}

	if a.isRecursion(dl) {
		a.result.count(dl, true)
	} else {
		a.result.count(dl, false)
	}
}

func (a *Analyzer) out() {
	if !a.begin {
		return
	}

	a.result.BeginTime = a.endTime.Local().Add(-a.interval)
	a.result.EndTime = a.endTime
	b := a.result.Json()

	if _, err := a.outLogger.Write([]byte("######################################\n")); err != nil {
		logger.Errorf("write file %s failed %s", a.outLogger.Filename)
	}

	if _, err := a.outLogger.Write(b); err != nil {
		logger.Errorf("write file %s failed %s", a.outLogger.Filename)
	}

	if _, err := a.outLogger.Write([]byte("\n")); err != nil {
		logger.Errorf("write file %s failed %s", a.outLogger.Filename)
	}

	logger.Infof("output analyze result succeed")
	a.result = NewResult(a.interval, a.ips, a.domains)
}

func (a *Analyzer) isRecursion(dl *types.Dnslog) bool {
	_, ok := a.selfIps[dl.SrcIP.String()]
	return ok && dl.DstPort == 53
}
