package qpshandler

import (
	"time"

	"github.com/hiwyw/dnscap-go/app/dnslog"
	"github.com/hiwyw/dnscap-go/app/logger"
)

const (
	statInterval = time.Second * 5
)

func New() *QpsHandler {
	h := &QpsHandler{
		ticker:  *time.NewTicker(statInterval),
		ch:      make(chan struct{}),
		closeCh: make(chan struct{}),
	}

	go h.loop()
	return h
}

type QpsHandler struct {
	queryCount uint64
	ticker     time.Ticker
	ch         chan struct{}
	closeCh    chan struct{}
}

func (q *QpsHandler) loop() {
	for {
		select {
		case _, ok := <-q.ch:
			if !ok {
				q.closeCh <- struct{}{}
				logger.Infof("qps handler exitting")
				return
			}
			q.queryCount++
		case <-q.ticker.C:
			logger.Infof("average packet resolve peer second %d", q.queryCount/5)
			q.queryCount = 0
		}
	}
}

func (q *QpsHandler) Handle(dl *dnslog.Dnslog) {
	q.ch <- struct{}{}
}

func (q *QpsHandler) Stop() {
	close(q.ch)
	<-q.closeCh
	q.ticker.Stop()
}
