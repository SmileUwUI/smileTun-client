package logger

import "log"

const (
	LogLevelError = 1
	LogLevelInfo  = 2
	LogLevelDebug = 3
	LogLevelTrace = 4
)

type Logger struct {
	level int
}

func NewLogger(level int) *Logger {
	return &Logger{level: level}
}

func (l *Logger) Error(format string, v ...interface{}) {
	if l.level >= LogLevelError {
		log.Printf("[ERROR] "+format, v...)
	}
}

func (l *Logger) Info(format string, v ...interface{}) {
	if l.level >= LogLevelInfo {
		log.Printf("[INFO] "+format, v...)
	}
}

func (l *Logger) Debug(format string, v ...interface{}) {
	if l.level >= LogLevelDebug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func (l *Logger) Trace(format string, v ...interface{}) {
	if l.level >= LogLevelTrace {
		log.Printf("[TRACE] "+format, v...)
	}
}
