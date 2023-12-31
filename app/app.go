package app

import (
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"path"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"

	"github.com/hiwyw/dnscap-go/app/config"
	"github.com/hiwyw/dnscap-go/app/handler"
	"github.com/hiwyw/dnscap-go/app/handler/analyzer"
	"github.com/hiwyw/dnscap-go/app/handler/logwriter"
	"github.com/hiwyw/dnscap-go/app/handler/qpswriter"
	"github.com/hiwyw/dnscap-go/app/logger"
	"github.com/hiwyw/dnscap-go/app/session"
	"github.com/hiwyw/dnscap-go/app/types"
)

const (
	snapshot_len = 1500

	timeout = 3 * time.Second

	promiscuous = true
)

func New(cfg *config.Config) *App {
	a := &App{
		cfg:          cfg,
		sessionCache: session.New(cfg.SessionCacheSize),
		handlers:     []handler.Handler{},
		closeCh:      make(chan struct{}),
	}

	if cfg.DnslogEnable {
		h := logwriter.New(
			path.Join(cfg.OutputDir, cfg.DnslogFilename),
			cfg.DnslogMaxsize,
			cfg.DnslogCount,
			cfg.DnslogAge)
		a.handlers = append(a.handlers, h)
	}

	if cfg.AnalyzeEnable {
		h := analyzer.New(
			path.Join(cfg.OutputDir, cfg.AnalyzeOutFilename),
			cfg.GetAnalyeInterval(),
			cfg.AnalyzeIps,
			cfg.AnalyzeDomains,
			cfg.SelfIps)
		a.handlers = append(a.handlers, h)
	}

	a.handlers = append(a.handlers, qpswriter.New())

	if cfg.PprofEnable {
		go pprof(cfg.PprofHttpPort)
	}

	return a
}

func pprof(port int) {
	http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", port), nil)
}

type App struct {
	cfg          *config.Config
	sessionCache *session.SessionCache
	handlers     []handler.Handler
	closeCh      chan struct{}
}

func (a *App) Run() {
	switch a.cfg.SourceType {
	case config.SourceTypePcap:
		a.handlePcap()
	case config.SourceTypePcapFile:
		a.handlePcapFiles()
	}
}

func (a *App) handlePcap() {
	handle, err := pcap.OpenLive(a.cfg.SourceDeviceName, snapshot_len, promiscuous, timeout)
	if err != nil {
		logger.Fatalf("open pcap device %s failed %s", a.cfg.SourceDeviceName, err)
		return
	}
	defer handle.Close()

	bpf := getBpfFilterString(a.cfg.GetFilterIps())
	if err := handle.SetBPFFilter(bpf); err != nil {
		logger.Fatalf("set bfp filter failed [%s] %s", bpf, err)
		return
	}
	logger.Infof("set bpf filter succeed [%s]", bpf)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	a.handlePacketSource(packetSource)
}

func (a *App) handlePcapFiles() {
	logger.Infof("total %d pcap files need to handle", len(a.cfg.SourcePcapFiles))
	for _, f := range a.cfg.SourcePcapFiles {
		logger.Infof("begin handle pcap file %s", f)
		if err := a.handleOnePacpFile(f); err != nil {
			logger.Errorf("handle pcap file %s failed %s", f, err)
		}
		logger.Infof("end handle pcap file %s", f)
	}
}

func (a *App) handleOnePacpFile(filename string) error {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return fmt.Errorf("open pacp file %s failed %s", filename, err)
	}
	defer handle.Close()

	bpf := getBpfFilterString(a.cfg.GetFilterIps())
	if err := handle.SetBPFFilter(bpf); err != nil {
		return fmt.Errorf("set bpf filter failed [%s] %s", bpf, err)
	}
	logger.Infof("set bpf filter succeed [%s]", bpf)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	a.handlePacketSource(packetSource)
	return nil
}

func (a *App) handlePacketSource(s *gopacket.PacketSource) {
	for {
		select {
		case p, ok := <-s.Packets():
			if !ok {
				logger.Infof("handle groutinue exiting by no packets")
				return
			}
			a.handleP(p)
		case <-a.closeCh:
			logger.Infof("handle groutinue exiting by close signal")
			a.closeCh <- struct{}{}
			return
		}
	}
}

func (a *App) handleP(p gopacket.Packet) {
	if p == nil {
		return
	}

	dl, err := unpack(p)
	if err != nil {
		logger.Debugf("unpack packet failed %s", err)
		return
	}

	if dl.Response {
		if err := a.matchSession(dl); err != nil {
			logger.Debugf("%s", err)
		}
	} else {
		a.add2Session(dl)
	}

	for _, h := range a.handlers {
		h.Handle(dl)
	}
}

func unpack(p gopacket.Packet) (*types.Dnslog, error) {
	dl := &types.Dnslog{}
	if p.Metadata() == nil {
		return nil, fmt.Errorf("packet metadata missing")
	}
	dl.PacketTime = p.Metadata().Timestamp

	ipLayer := p.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, ok := ipLayer.(*layers.IPv4)
		if !ok {
			return nil, fmt.Errorf("packet convert ip layer to ipv4 failed")
		}
		dl.SrcIP = ip.SrcIP
		dl.DstIP = ip.DstIP
	} else {
		ipLayer := p.Layer(layers.LayerTypeIPv6)
		if ipLayer == nil {
			return nil, fmt.Errorf("packet missing ip layer")
		}
		ip, ok := ipLayer.(*layers.IPv6)
		if !ok {
			return dl, fmt.Errorf("packet convert ip layer to ipv6 failed")
		}
		dl.SrcIP = ip.SrcIP
		dl.DstIP = ip.DstIP
	}

	udpLayer := p.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return dl, fmt.Errorf("packet missing udp layer")
	}
	udp, ok := udpLayer.(*layers.UDP)
	if !ok {
		return dl, fmt.Errorf("packet convert udp layer to udp failed")
	}
	dl.SrcPort = uint16(udp.SrcPort)
	dl.DstPort = uint16(udp.DstPort)

	msg := new(dns.Msg)
	if err := msg.Unpack(udp.Payload); err != nil {
		return dl, fmt.Errorf("packet unpack to dns msg failed %s", err)
	}

	types.DnslogFromMsg(msg, dl)
	return dl, nil
}

func getBpfFilterString(ips []net.IP) string {
	if len(ips) == 0 {
		return "udp and port 53"
	}

	s := ""

	hss := []string{}
	for _, ip := range ips {
		hs := fmt.Sprintf("host %s ", ip.String())
		hss = append(hss, hs)
	}
	s += strings.Join(hss, "or ")

	s += "and udp and port 53"
	return s
}

func (a *App) add2Session(dl *types.Dnslog) {
	k := session.SessionKey{
		SrcIP:   dl.SrcIP.String(),
		DstIP:   dl.DstIP.String(),
		SrcPort: dl.SrcPort,
		DstPort: dl.DstPort,
		TransID: dl.TransID,
	}

	v := session.SessionValue{
		QueryTime: dl.PacketTime,
		QueryType: dl.QueryType,
		Domain:    dl.Domain,
	}
	if a.sessionCache.Add(k, v) {
		logger.Errorf("session cache evict occured")
	}
}

func (a *App) matchSession(dl *types.Dnslog) error {
	k := session.SessionKey{
		SrcIP:   dl.DstIP.String(),
		DstIP:   dl.SrcIP.String(),
		SrcPort: dl.DstPort,
		DstPort: dl.SrcPort,
		TransID: dl.TransID,
	}

	v, ok := a.sessionCache.Find(k)
	if !ok {
		return fmt.Errorf("match session failed [src:%s dst:%s srcport:%d dstport:%d transid:%d]", k.SrcIP, k.DstIP, k.SrcPort, k.DstPort, k.TransID)
	}

	if dl.QueryType != v.QueryType || dl.Domain != v.Domain {
		return fmt.Errorf("match session failed by querytype or domain not match [%s %s]", dl.QueryType, dl.Domain)
	}
	defer a.sessionCache.Delete(k)

	dl.ResolvDuration = dl.PacketTime.Sub(v.QueryTime)
	return nil
}

func (a *App) Stop() {
	a.closeCh <- struct{}{}
	<-a.closeCh

	for _, h := range a.handlers {
		h.Stop()
	}

	logger.Infof("all handler exited")
}
