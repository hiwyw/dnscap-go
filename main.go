package main

import (
	"flag"
	"log"

	"github.com/hiwyw/dnscap-go/app"
	"github.com/hiwyw/dnscap-go/app/config"
	"github.com/hiwyw/dnscap-go/app/logger"
	"github.com/hiwyw/dnscap-go/app/pkg/signal"
)

var (
	genConfig    bool
	printVersion bool

	configFile   string
	buildTime    string = "2023-8-31"
	buildVersion string = "v0.1.1"
)

func main() {
	flag.StringVar(&configFile, "config", "config.yaml", "config file")
	flag.BoolVar(&genConfig, "gen", false, "gen demo config file")
	flag.BoolVar(&printVersion, "version", false, "print version")
	flag.Parse()

	if printVersion {
		log.Printf("build at %s version %s", buildTime, buildVersion)
		return
	}

	if genConfig {
		config.Generate(configFile)
		log.Printf("gen demo config %s succeed", configFile)
		return
	}

	c := config.Load(configFile)
	logger.InitLogger(c)
	a := app.New(c)
	go a.Run()
	signal.WaitForInterrupt(func() {
		a.Stop()
		logger.Get().Infof("recvice interrupt signal, exitting")
		logger.Get().Infof("main groutinue exitting")
	})
}
