package handler

import (
	"github.com/hiwyw/dnscap-go/app/dnslog"
)

type Handler interface {
	Handle(dl *dnslog.Dnslog)
	Stop()
}
