package logwriter

import (
	"bufio"
	"time"

	"github.com/hiwyw/dnscap-go/app/logger"
	"github.com/hiwyw/dnscap-go/app/types"
	"github.com/natefinch/lumberjack"
)

const (
	batchWriteTimeout = time.Second * 1
)

type LogHandler struct {
	writer  *lumberjack.Logger
	buffer  *bufio.Writer
	logCh   chan *types.Dnslog
	closeCh chan struct{}
}

func New(filename string, maxsize, fileCount, fileAge int) *LogHandler {
	h := &LogHandler{
		writer: &lumberjack.Logger{
			Filename:   filename,
			MaxSize:    maxsize,
			MaxBackups: fileCount,
			MaxAge:     fileAge,
			Compress:   true,
		},
		closeCh: make(chan struct{}),
		logCh:   make(chan *types.Dnslog, 100),
	}
	h.buffer = bufio.NewWriterSize(h.writer, 1024*8)

	go h.loop()
	return h
}

func (h *LogHandler) loop() {
	for {
		select {
		case l, ok := <-h.logCh:
			if !ok {
				h.buffer.Flush()
				h.closeCh <- struct{}{}
				logger.Infof("log handler exiting")
				return
			}
			h.handle(l)
		case <-time.After(batchWriteTimeout):
			h.buffer.Flush()
		}
	}
}

func (h *LogHandler) Handle(dl *types.Dnslog) {
	h.logCh <- dl
}

func (h *LogHandler) handle(dl *types.Dnslog) {
	if _, err := h.buffer.WriteString(dl.String()); err != nil {
		logger.Panicf("write file %s failed %s", h.writer.Filename, err)
	}

	if _, err := h.buffer.WriteString("\n"); err != nil {
		logger.Panicf("write file %s failed %s", h.writer.Filename, err)
	}

	if h.buffer.Available() < 2048 {
		if err := h.buffer.Flush(); err != nil {
			logger.Panicf("write file %s failed %s", h.writer.Filename, err)
		}
	}
}

func (h *LogHandler) Stop() {
	close(h.logCh)
	<-h.closeCh
	h.writer.Close()
}
