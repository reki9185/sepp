//+build debug

package util

import (
	"github.com/free5gc/path_util"
)

var (
	SeppLogPath           = path_util.Free5gcPath("free5gc/seppsslkey.log")
	SeppPemPath           = path_util.Free5gcPath("free5gc/support/TLS/sepp.pem")
	SeppKeyPath           = path_util.Free5gcPath("free5gc/support/TLS/sepp.key")
	DefaultSeppConfigPath = path_util.Free5gcPath("free5gc/config/seppcfg.yaml")
)
