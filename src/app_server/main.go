// Copyright 2016 Comcast Cable Communications Management, LLC

package main

import (
	"log"
	"net/http"
	"io/ioutil"
	"os"
	"os/signal"
	"encoding/json"
	"path/filepath"
	"syscall"
	"time"
	"github.com/httprouter"
	"github.com/cors"
)

var (
	Trace   *log.Logger
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
	Config Configuration
)

// The first letter of the struct elements must be upper case in order to export them
// The JSON decoder will not use struct elements that are not exported
type Configuration struct {
	Log_file string
	Fqdn string
	Ssl_cert_file string
	Ssl_key_file string
	Canon bool
	Authentication map[string]interface{} `json:"authentication"`	// unmarshals a JSON object into a string-keyed map
}

// Read from configuration file and validate keys exist
func getConfiguration(config_file string) (err error) {
	file, err := os.Open(config_file)
	if err == nil {
		decoder := json.NewDecoder(file)
		err = decoder.Decode(&Config)
	}
	return
}

// Instantiate logging objects
func initializeLogging() (err error) {
	err = os.MkdirAll(filepath.Dir(Config.Log_file), 0755)
	if err == nil {
		file, err := os.OpenFile(Config.Log_file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			Trace = log.New(ioutil.Discard, "Code=TRACE ", log.Ldate|log.Ltime|log.Lshortfile) 
			Info = log.New(file, "", 0)
			Warning = log.New(file, "Code=WARNING, ", log.Ldate|log.Ltime|log.Lshortfile)
			Error = log.New(file, "", 0)
		}
	}
	return
}

// function to log in specific format
func logInfo(format string, args ...interface{}) {
	Info.Printf(time.Now().Format("2006-01-02 15:04:05") + " appsrvr=" + Config.Fqdn + ", Code=Info, Message=" + format, args ...)
}

// function to log in specific format
func logError(format string, args ...interface{}) {
	Error.Printf(time.Now().Format("2006-01-02 15:04:05") + " appsrvr=" + Config.Fqdn + ", Code=Error, Message=" + format, args ...)
}

// Read config file
// Instantiate logging
func init() {
	if (len(os.Args) != 2) {
		log.Fatal("The config file (ABSOLUTE PATH + FILE NAME) must be the only command line arguement")	
	}
	// read config
	err  := getConfiguration(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}	
	
	// Initialize logging
	err = initializeLogging()
	if err != nil {
		log.Fatal(err)
	}	
}

func handle_signals() {
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt)
    signal.Notify(c, syscall.SIGTERM)
    go func() {
        <-c
        logInfo("Shutting down app server .... ")
        os.Exit(1)
    }()
}

// 
func main() {
	logInfo("Starting app server .... ")
	handle_signals()
	
	router := httprouter.New()
	router.POST("/v1/sippacket", process_sip_message)
	router.GET("/v1/version", version)
	
	// Start the service.
	// Note: netstats -plnt shows a IPv6 TCP socket listening on localhost:9000
	//       but no IPv4 TCP socket. This is not an issue
	c := cors.New(cors.Options{
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"accept", "Content-Type", "Authorization"},
		AllowCredentials: true,
	})
	handler := c.Handler(router)
	errs := make(chan error)

	// Starting HTTP server
 	go func() {
		logInfo("Staring HTTP service on port 80 ...")
		// Start the service.
		// Note: netstats -plnt shows a IPv6 TCP socket listening on ":80"
		//       but no IPv4 TCP socket. This is not an issue
		if err := http.ListenAndServe(":80", handler); err != nil {
			errs <- err
		}
	 }()
	// Starting HTTPS server
	go func() {
		logInfo("Staring HTTPS service on port 443 ...")
		// Note: netstats -plnt shows a IPv6 TCP socket listening on ":443"
		//       but no IPv4 TCP socket. This is not an issue
		if err := http.ListenAndServeTLS(":443", Config.Ssl_cert_file, Config.Ssl_key_file, handler); err != nil {
			errs <- err
		}
	}()
	// This will run forever until channel receives error
	select {
	case err := <-errs:
		logError("Could not start serving service due to (error: %s)", err)
	}
}
