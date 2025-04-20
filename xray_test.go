package xray

import (
	log "github.com/sirupsen/logrus"
)

var x = NewXray()

func init() {
	err := x.Start("./", []byte("{}"))
	if err != nil {
		log.Fatal(err)
	}
}
