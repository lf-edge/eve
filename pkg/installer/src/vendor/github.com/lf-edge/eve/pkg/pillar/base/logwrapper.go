package base

import "github.com/sirupsen/logrus"

// LogrusWrapper wraps LogObject to implement the same interface as the
// widely used Sirupsen/Logrus (see https://github.com/sirupsen/logrus)
// This may allow to use LogObject in libraries outside of pillar.
// However, only methods with formatted output are wrapped for now.
type LogrusWrapper struct {
	Log *LogObject
}

// Tracef : formatted log message with info useful for finer-grained debugging.
func (w *LogrusWrapper) Tracef(format string, args ...interface{}) {
	w.Log.Tracef(format, args...)
}

// Debugf : formatted log message with info useful for debugging.
func (w *LogrusWrapper) Debugf(format string, args ...interface{}) {
	if myFunctionLevel == logrus.DebugLevel {
		w.Log.Functionf(format, args...)
		return
	}
	if myNoticeLevel == logrus.DebugLevel {
		w.Log.Noticef(format, args...)
		return
	}
	// Default (method with Debug level is not available)
	w.Log.Functionf(format, args...)
}

// Infof : formatted log message with a general info about what's going on
// inside the application.
func (w *LogrusWrapper) Infof(format string, args ...interface{}) {
	if myNoticeLevel == logrus.InfoLevel {
		w.Log.Noticef(format, args...)
		return
	}
	if myFunctionLevel == logrus.InfoLevel {
		w.Log.Functionf(format, args...)
		return
	}
	// Default (method with Info level is not available)
	w.Log.Noticef(format, args...)
}

// Warningf : formatted log message with a warning.
func (w *LogrusWrapper) Warningf(format string, args ...interface{}) {
	w.Log.Warningf(format, args...)
}

// Errorf : formatted log message with an error.
func (w *LogrusWrapper) Errorf(format string, args ...interface{}) {
	w.Log.Errorf(format, args...)
}

// Fatalf : formatted log message with an error, ending with a call to os.Exit()
// with a non-zero return value.
func (w *LogrusWrapper) Fatalf(format string, args ...interface{}) {
	w.Log.Fatalf(format, args...)
}

// Panicf : formatted log message with an error, raising a panic.
func (w *LogrusWrapper) Panicf(format string, args ...interface{}) {
	w.Log.Panicf(format, args...)
}
