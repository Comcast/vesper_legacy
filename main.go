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
	"github.com/julienschmidt/httprouter"
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
	Authentication map[string]interface{} `json:"authentication"`	// unmarshals a JSON object into a string-keyed map
	Verification map[string]interface{} `json:"verification"`	// unmarshals a JSON object into a string-keyed map
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
	err := http.ListenAndServe(":9000", router)
	if err != nil {
		logError("Shutting down - %s", err)
		log.Fatal(err)
	}
	logInfo("Serving HTTP on port 9000")
	log.Fatal(http.ListenAndServe(":9000", nil))
}
