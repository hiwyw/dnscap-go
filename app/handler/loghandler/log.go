package loghandler

import (
	"github.com/hiwyw/dnscap-go/app/logger"
	"github.com/natefinch/lumberjack"
)

type LogHandler struct {
	*lumberjack.Logger
}

func New(filename string, maxsize, fileCount, fileAge int) *LogHandler {
	return &LogHandler{
		&lumberjack.Logger{
			Filename:   filename,
			MaxSize:    maxsize,
			MaxBackups: fileCount,
			MaxAge:     fileAge,
			Compress:   true,
		},
	}
}

func (h *LogHandler) Handle(s string) {
	if _, err := h.Write([]byte(s)); err != nil {
		logger.Get().Errorf("write file %s failed %s", h.Filename)
	}

	if _, err := h.Write([]byte("\n")); err != nil {
		logger.Get().Errorf("write file %s failed %s", h.Filename)
	}
}

func (h *LogHandler) Stop() {
	h.Close()
}
