package handler

import (
	"github.com/hiwyw/dnscap-go/app/types"
)

type Handler interface {
	Handle(dl *types.Dnslog)
	Stop()
}
