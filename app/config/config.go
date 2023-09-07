package config

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v2"
)

func Load(fp string) *Config {
	c := &Config{}

	fileContent, err := os.ReadFile(fp)
	if err != nil {
		log.Fatalf("read config file %s failed %s", fp, err)
	}

	if err := yaml.Unmarshal(fileContent, c); err != nil {
		log.Fatalf("unmarshal config failed %s", err)
	}

	if err := c.Validate(); err != nil {
		log.Fatalf("validate config failed %s", err)
	}

	domains := []string{}
	for _, d := range c.AnalyzeDomains {
		domains = append(domains, dns.Fqdn(d))
	}
	c.AnalyzeDomains = domains

	return c
}

func Generate(fp string) {
	c := &Config{
		SourceType: SourceTypePcapFile,
		SourcePcapFiles: []string{
			"dns.pcap00",
			"dns.pcap01",
			"dns.pcap02",
		},
		FilterIps: []string{},
		OutputDir: "./dnscap_result",
		SelfIps: []string{
			"192.168.134.200",
			"192.168.135.200",
		},
		SessionCacheSize:   100000,
		DnslogEnable:       true,
		DnslogFilename:     "dns.log",
		DnslogMaxsize:      50,
		DnslogCount:        100,
		DnslogAge:          30,
		AnalyzeEnable:      false,
		AnalyzeOutFilename: "analyze.log",
		AnalyzeInterval:    "5m",
		AnalyzeIps: []string{
			"192.168.134.201",
			"192.168.134.202",
		},
		AnalyzeDomains: []string{
			"www.test.com.",
		},
		PprofEnable:   false,
		PprofHttpPort: 8000,
	}

	content, err := yaml.Marshal(c)
	if err != nil {
		log.Fatalf("config yaml marshal failed %s", err)
	}

	if err := os.WriteFile(fp, content, 0644); err != nil {
		log.Fatalf("config yaml marshal failed %s", err)
	}
	log.Printf("config file %s generated", fp)
}

type InputSourceType string

const (
	SourceTypePcapFile InputSourceType = "packet_file"
	SourceTypePcap     InputSourceType = "packet_capture"
)

type Config struct {
	SourceType         InputSourceType `yaml:"source_type"`
	SourcePcapFiles    []string        `yaml:"source_pcap_files"`
	SourceDeviceName   string          `yaml:"source_device_name"`
	FilterIps          []string        `yaml:"filter_ips"`
	OutputDir          string          `yaml:"output_dir"`
	SelfIps            []string        `yaml:"self_ips"`
	SessionCacheSize   int             `yaml:"session_cache_size"`
	DnslogEnable       bool            `yaml:"dnslog_enable"`
	DnslogFilename     string          `yaml:"dnslog_filename"`
	DnslogMaxsize      int             `yaml:"dnslog_maxsize"`
	DnslogCount        int             `yaml:"dnslog_count"`
	DnslogAge          int             `yaml:"dnslog_age"`
	AnalyzeEnable      bool            `yaml:"analyze_enable"`
	AnalyzeOutFilename string          `yaml:"analyzeOutFilename"`
	AnalyzeInterval    string          `yaml:"analyze_interval"`
	AnalyzeIps         []string        `yaml:"analyze_querycount_ips"`
	AnalyzeDomains     []string        `yaml:"analyze_querycount_domains"`
	PprofEnable        bool            `yaml:"pprof_enable"`
	PprofHttpPort      int             `yaml:"pprof_http_port"`
}

func (c *Config) Validate() error {
	if c.SourceType == "" {
		return fmt.Errorf("unknown source type %s", c.SourceType)
	}

	if c.SourceType == SourceTypePcapFile {
		if len(c.SourcePcapFiles) == 0 {
			return errors.New("no source pcap files")
		}
	}

	if c.SourceType == SourceTypePcap && c.SourceDeviceName == "" {
		return errors.New("source device name empty")
	}

	if !c.DnslogEnable && !c.AnalyzeEnable {
		return errors.New("both dnslog and analyze disabled")
	}

	for _, d := range c.AnalyzeDomains {
		if _, ok := dns.IsDomainName(d); !ok {
			if !ok {
				return fmt.Errorf("%d not domain name", d)
			}
		}
	}

	_ = c.GetFilterIps()
	_ = c.GetAnalyzeQueryCountIps()
	_ = c.GetSelfIps()
	_ = c.GetAnalyeInterval()

	return nil
}

func (c *Config) GetFilterIps() []net.IP {
	return strings2Ips(c.FilterIps)
}

func (c *Config) GetSelfIps() []net.IP {
	return strings2Ips(c.SelfIps)
}

func (c *Config) GetAnalyzeQueryCountIps() []net.IP {
	return strings2Ips(c.AnalyzeIps)
}

func strings2Ips(input []string) []net.IP {
	ips := []net.IP{}
	for _, i := range input {
		ip := net.ParseIP(i)
		if ip == nil {
			log.Fatalf("parse ip failed %s", i)
		}
		ips = append(ips, ip)
	}
	return ips
}

func (c *Config) GetAnalyeInterval() time.Duration {
	d, err := time.ParseDuration(c.AnalyzeInterval)
	if err != nil {
		log.Fatalf("parse analyinterval failed %s", c.AnalyzeInterval)
	}
	return d
}
