// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"github.com/sirupsen/logrus"
)

// We map our notions of levels to the logrus levels
// The Notice, Metric, and Function functions/levels are unique to enable
// more flexibility during EVE development.
var (
	myNoticeLevel   = logrus.InfoLevel
	myMetricLevel   = logrus.DebugLevel
	myFunctionLevel = logrus.DebugLevel
)

// Function :
func (object *LogObject) Function(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Log(myFunctionLevel, args...)
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

// Functionf :
func (object *LogObject) Functionf(format string, args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Logf(myFunctionLevel, format, args...)
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

// Functionln :
func (object *LogObject) Functionln(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Logln(myFunctionLevel, args...)
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
	object.logger.WithFields(object.Fields).Trace(args...)
}

// Tracef :
func (object *LogObject) Tracef(format string, args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Tracef(format, args...)
}

// Traceln :
func (object *LogObject) Traceln(args ...interface{}) {
	if !object.Initialized {
		logrus.Fatal("LogObject used without initialization")
		return
	}
	object.logger.WithFields(object.Fields).Traceln(args...)
}
