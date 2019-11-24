# personal-site

## Goals

### infrastructure

* Raspberry-pi
* Running from home
* CDN as DNS / Protection

### server

* ~~Since its on a pi, it will need to handle TLS~~
  * ~~Should be able to handle this with [LE](https://blog.kowalczyk.info/article/Jl3G/https-for-free-in-go-with-little-help-of-lets-encrypt.html)~~
* ~~Lets try caching the cert in [badger](https://github.com/dgraph-io/badger)~~
* Site is fronted by a CDN, but is still serving a letsEncrypt cert.
  * Tried to have the server grab and serve its own cert by using acme/autocert, however couldn't get this to properly receive its cert; even using the most basic example. (Possible issue with .dev domains?)
  * Instead I use certbot and point to the symlinked certs.
* Serve site data from go templates [ex](https://golang.org/doc/articles/wiki/)
* Get and present metrics on the site

### site

* I don't think this needs a framework.
* Pages:
  * home - generic description about site
  * projects - list of projects I want to share / show off
  * resume - do I want to put a resume on this?
  * wiki / gist - a place to store snippets and shit (authentication? don't want anyone able to create / edit)
  * contact me - ?

## Codebase

### internal

* server:
  * server.go
    * this file handles starting and stopping the net/http server
  * config.go
    * this file handles general configuration of the server. Referenced by server.go and cert.go
    * config contains:
      * Production bool
        * if true only server on 443 else only serve on 8080
        * CertFile string
        * KeyFile string
        * ReadTimeout int (converted to time.duration)
        * WriteTimeout int (converted to time.duration)
        * IdleTimeout int (converted to time.duration)
