package main

import (
	"flag"
	"log"
	"os"

	"github.com/elliottpope/share-d/backends"
	"github.com/elliottpope/share-d/server"
)

// HTTPError ... encapsulates details of an HTTP Error to be raised and displayed to the client
type HTTPError struct {
	HTTPCode int    `json:"-"`
	Message  string `json:"error-message"`
	Code     string `json:"error-code,omitempty"`
	Cause    error  `json:"-"`
}

// Configuration ... data structure for holding the confguration of the Share-d server
type Configuration struct {
	Backend string
}

var (
	config  *Configuration = &Configuration{}
	backend *backends.Backend

	// ErrorLogger ... global error logger
	ErrorLogger *log.Logger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
)

func main() {
	backendLocation := flag.String("backend", "./data", "the location to store secrets and metadata")

	flag.Parse()

	config.Backend = *backendLocation

	if _, err := os.Stat(*backendLocation); os.IsNotExist(err) {
		os.Mkdir(*backendLocation, 0666)
	}

	backend := &backends.FileBackend{
		BasePath: config.Backend,
	}

	server := &server.Server{
		Backend:     backend,
		ErrorLogger: ErrorLogger,
	}

	server.Start()

}
