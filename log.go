package main

import "log"

const (
	LOG_ERROR = 3
	LOG_WARNING = 4
	LOG_INFO = 6
	LOG_DEBUG = 7
)

var MAX_LOGLEVEL = LOG_INFO

func mylog(severity int, format string, v ...any) {
	if severity > MAX_LOGLEVEL {
		return
	}
	if cfg.log_prefix != "" {
		format = cfg.log_prefix + " " + format
	}
	log.Printf(format, v...)
}

func log_err(format string, v ...any) {
	mylog(LOG_ERROR, format, v...)
}

func log_warn(format string, v ...any) {
	mylog(LOG_WARNING, format, v...)
}

func log_info(format string, v ...any) {
	mylog(LOG_INFO, format, v...)
}

func log_debug(format string, v ...any) {
	mylog(LOG_DEBUG, format, v...)
}

func log_fatal(format string, v ...any) {
	log.Fatalf(format, v...)
}
