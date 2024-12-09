package main

import (
	"github.com/InazumaV/Ratte-Interface/core"
	log "github.com/sirupsen/logrus"
)

func main() {
	c, err := core.NewServer(nil, NewXray())
	if err != nil {
		log.Fatalln(err)
	}
	if err = c.Run(); err != nil {
		log.Fatalln(err)
	}
}
