// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"github.com/sirupsen/logrus"
)

// We map our notions of levels to the logrus levels
// XXX should we make this mapping configurable?
// The Notice and Metric functions/levels are unique
// XXX should we rename the callers of Info* and Debug* to Debug* and Trace*, respectively
var (
	myNoticeLevel = logrus.InfoLevel
	myMetricLevel = logrus.DebugLevel
	myInfoLevel   = logrus.DebugLevel
	myDebugLevel  = logrus.TraceLevel
	myTraceLevel  = logrus.TraceLevel
)

// Debug :
func (object *LogObject) Debug(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Log(myDebugLevel, args...)
}

// Info :
func (object *LogObject) Info(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Log(myInfoLevel, args...)
}

// Warn :
func (object *LogObject) Warn(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Warn(args...)
}

// Warning :
func (object *LogObject) Warning(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Warning(args...)
}

// Error :
func (object *LogObject) Error(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Error(args...)
}

// Panic :
func (object *LogObject) Panic(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Panic(args...)
}

// Fatal :
func (object *LogObject) Fatal(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Fatal(args...)
}

// Debugf :
func (object *LogObject) Debugf(format string, args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Logf(myDebugLevel, format, args...)
}

// Infof :
func (object *LogObject) Infof(format string, args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Logf(myInfoLevel, format, args...)
}

// Warnf :
func (object *LogObject) Warnf(format string, args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Warnf(format, args...)
}

// Warningf :
func (object *LogObject) Warningf(format string, args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Warningf(format, args...)
}

// Panicf :
func (object *LogObject) Panicf(format string, args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Panicf(format, args...)
}

// Fatalf :
func (object *LogObject) Fatalf(format string, args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Fatalf(format, args...)
}

// Errorf :
func (object *LogObject) Errorf(format string, args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Errorf(format, args...)
}

// Debugln :
func (object *LogObject) Debugln(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Logln(myDebugLevel, args...)
}

// Infoln :
func (object *LogObject) Infoln(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Logln(myInfoLevel, args...)
}

// Warnln :
func (object *LogObject) Warnln(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Warnln(args...)
}

// Warningln :
func (object *LogObject) Warningln(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Warningln(args...)
}

// Errorln :
func (object *LogObject) Errorln(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Errorln(args...)
}

// Panicln :
func (object *LogObject) Panicln(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Panicln(args...)
}

// Fatalln :
func (object *LogObject) Fatalln(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Fatalln(args...)
}

// Notice :
func (object *LogObject) Notice(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Log(myNoticeLevel, args...)
}

// Noticef :
func (object *LogObject) Noticef(format string, args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Logf(myNoticeLevel, format, args...)
}

// Noticeln :
func (object *LogObject) Noticeln(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Logln(myNoticeLevel, args...)
}

// Metric :
func (object *LogObject) Metric(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Log(myMetricLevel, args...)
}

// Metricf :
func (object *LogObject) Metricf(format string, args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Logf(myMetricLevel, format, args...)
}

// Metricln :
func (object *LogObject) Metricln(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Logln(myMetricLevel, args...)
}

// Trace :
func (object *LogObject) Trace(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Log(myTraceLevel, args...)
}

// Tracef :
func (object *LogObject) Tracef(format string, args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Logf(myTraceLevel, format, args...)
}

// Traceln :
func (object *LogObject) Traceln(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Logln(myTraceLevel, args...)
}
