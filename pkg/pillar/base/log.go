// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	log "github.com/sirupsen/logrus"
)

// Debug :
func (object *LogObject) Debug(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Debug(args...)
}

// Print :
func (object *LogObject) Print(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Print(args...)
}

// Info :
func (object *LogObject) Info(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Info(args...)
}

// Warn :
func (object *LogObject) Warn(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Warn(args...)
}

// Warning :
func (object *LogObject) Warning(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Warning(args...)
}

// Panic :
func (object *LogObject) Panic(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Panic(args...)
}

// Fatal :
func (object *LogObject) Fatal(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Fatal(args...)
}

// Debugf :
func (object *LogObject) Debugf(format string, args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Debugf(format, args...)
}

// Infof :
func (object *LogObject) Infof(format string, args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Infof(format, args...)
}

// Warnf :
func (object *LogObject) Warnf(format string, args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Warnf(format, args...)
}

// Warningf :
func (object *LogObject) Warningf(format string, args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Warningf(format, args...)
}

// Panicf :
func (object *LogObject) Panicf(format string, args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Panicf(format, args...)
}

// Fatalf :
func (object *LogObject) Fatalf(format string, args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Fatalf(format, args...)
}

// Errorf :
func (object *LogObject) Errorf(format string, args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Errorf(format, args...)
}

// Debugln :
func (object *LogObject) Debugln(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Debugln(args...)
}

// Println :
func (object *LogObject) Println(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Println(args...)
}

// Infoln :
func (object *LogObject) Infoln(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Infoln(args...)
}

// Warnln :
func (object *LogObject) Warnln(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Warnln(args...)
}

// Warningln :
func (object *LogObject) Warningln(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Warningln(args...)
}

// Errorln :
func (object *LogObject) Errorln(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Errorln(args...)
}

// Panicln :
func (object *LogObject) Panicln(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Panicln(args...)
}

// Fatalln :
func (object *LogObject) Fatalln(args ...interface{}) {
	if !object.Initialized {
		log.Errorf("LogObject used without initialization")
		return
	}
	log.WithFields(object.Fields).Fatalln(args...)
}
