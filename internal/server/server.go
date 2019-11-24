package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type neuteredFileSystem struct {
	fs http.FileSystem
}

// Open checks if the requested path is a directory or not. If it is
// a directory, attempt to open any index.html file. If no index.html
// file exists return a NotExist, otherwise just return the file.
func (nfs neuteredFileSystem) Open(path string) (http.File, error) {
	f, err := nfs.fs.Open(path)
	if err != nil {
		return nil, err
	}

	s, err := f.Stat()
	if s.IsDir() {
		index := strings.TrimSuffix(path, "/") + "/index.html"
		if _, err := nfs.fs.Open(index); err != nil {
			return nil, err
		}
	}

	return f, nil
}

func (s *Configuration) makeServerFromMux(mux *http.ServeMux) *http.Server {
	port := fmt.Sprintf(":%d", s.DevPort)
	// set timeouts so that a slow or malicious client doesn't
	// hold resources forever
	return &http.Server{
		Addr:         port, // This is overwritten if s.Production=true.
		ReadTimeout:  s.ReadTimeout * time.Second,
		WriteTimeout: s.WriteTimeout * time.Second,
		IdleTimeout:  s.IdleTimeout * time.Second,
		Handler:      mux,
	}
}

func (s *Configuration) makeHTTPServer() *http.Server {
	mux := http.NewServeMux()
	fileServer := http.FileServer(neuteredFileSystem{http.Dir("web")})
	mux.Handle("/", http.StripPrefix("/", fileServer))
	return s.makeServerFromMux(mux)

}

// Start sets up the server based on the passed configuration.
// Either starting the server with tls or without.
func (s *Configuration) Start() {
	var err error

	if s.Production {
		s.HTTPServer = s.makeHTTPServer()     // Use the http.Server struct returned from makeServerFromMux as a foundation.
		s.HTTPServer.Addr = ":443"            // Because its my personal server, I only want to run in "prod" using 443. I am sure this wont come back to bite me.
		s.HTTPServer.TLSNextProto = nil       // ensure that this isn't an empty map as that would disable HTTP/2
		s.HTTPServer.TLSConfig = &tls.Config{ // Add the TLS config defined here to the httpServer defined above.
			MinVersion:               tls.VersionTLS12,                         // don't allow TLS lower than v1.2
			CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256}, // Only use curves which have assembly implementations
			PreferServerCipherSuites: true,                                     // Ensures safer and faster cipher suites are preferred
			CipherSuites: []uint16{ // Only Ciphers that provide Forward Secrecy
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			NextProtos: []string{"h2", "http/1.1"}, // enables HTTP/2
		}
		log.Infof("starting HTTPS server on %s\n", s.HTTPServer.Addr)
		err = s.HTTPServer.ListenAndServeTLS(s.CertFile, s.KeyFile) // Serve the site using TLS and the config above, note this blocks
		if err != http.ErrServerClosed {
			log.WithError(err).Error("http Server stopped unexpected")
			s.Shutdown()
		} else {
			log.WithError(err).Info("http Server stopped")
		}
	} else {
		s.HTTPServer = s.makeHTTPServer() // Use the http.Server struct returned from makeServerFromMux.
		log.Infof("starting HTTP server on %s\n", s.HTTPServer.Addr)
		err = s.HTTPServer.ListenAndServe() // Serve the site without TLS since "Production" isn't set, note this blocks
		if err != http.ErrServerClosed {
			log.WithError(err).Error("http Server stopped unexpected")
			s.Shutdown() // If there is an error try to shutdown the server gracefully
		} else {
			log.WithError(err).Info("http Server stopped")
		}
	}
}

// Shutdown attempts to shutdown the server gracefully.
func (s *Configuration) Shutdown() {
	log.Info("shutting down server")
	if s.HTTPServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // Set a context with a timeout of 10 seconds
		defer cancel()                                                           // Defer the cancel to avoid context leak
		err := s.HTTPServer.Shutdown(ctx)                                        // Attempt to shutdown the Server with the 10 second timeout context
		if err != nil {
			log.WithError(err).Error("failed to shutdown http server gracefully")
		} else {
			s.HTTPServer = nil // Set the httpServer to nil to force server to stop serving
		}
	}
}
