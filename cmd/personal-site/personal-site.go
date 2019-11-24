package main

import (
	"personal-site/internal/server"

	log "github.com/sirupsen/logrus"
)

func main() {
	server, err := server.NewConfig()
	if err != nil {
		log.WithError(err).Fatal("error calling server.NewConfig")
	}

	server.Start()
}
