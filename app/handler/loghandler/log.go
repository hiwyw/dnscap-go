package loghandler

import (
	"bufio"

	"github.com/hiwyw/dnscap-go/app/logger"
	"github.com/natefinch/lumberjack"
)

type LogHandler struct {
	writer  *lumberjack.Logger
	buffer  *bufio.Writer
	logCh   chan string
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
		logCh:   make(chan string, 100),
	}
	h.buffer = bufio.NewWriterSize(h.writer, 1024*8)

	go h.loop()
	return h
}

func (h *LogHandler) loop() {
	for {
		l, ok := <-h.logCh
		if !ok {
			h.buffer.Flush()
			h.closeCh <- struct{}{}
			return
		}
		h.handle(l)
	}
}

func (h *LogHandler) Handle(s string) {
	h.logCh <- s
}

func (h *LogHandler) handle(s string) {
	if _, err := h.buffer.WriteString(s); err != nil {
		logger.Get().Errorf("write file %s failed %s", h.writer.Filename, err)
	}

	if _, err := h.buffer.WriteString("\n"); err != nil {
		logger.Get().Errorf("write file %s failed %s", h.writer.Filename, err)
	}

	if h.buffer.Available() < 4096 {
		if err := h.buffer.Flush(); err != nil {
			logger.Get().Errorf("write file %s failed %s", h.writer.Filename, err)
		}
	}
}

func (h *LogHandler) Stop() {
	close(h.logCh)
	<-h.closeCh
	h.writer.Close()
}
