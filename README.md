![alt tag](https://github.com/Comcast/vesper/blob/master/stir.png)
![alt tag](https://github.com/Comcast/vesper/blob/master/shaken.png)
# vesper - Secure Telephone Identity Management

The repository hosts the code to run the application server which supports rfc4474bis and PASSporT style authentication service and verification service. It is implemented with an HTTP RESTful API interface for flexibility.  When the originating call sends the SIP INVITE payload via HTTP/HTTPS, the application vesper server retrieves the appropriate private key and signs the SIP INVITE based on rfc4474bis and passes the signed INVITE back to the SIP proxy. The terminating SIP proxy passes the received SIP invite via HTTP/HTTPS
to the application server to validate the signature in the identity header. 

**NOTE: This is a work in progress project and has not implemented the 4474bis specification in its entirety.**

## Installation

This application has been tested on Ubuntu 14.04 and Centos 7.1. The assumption is that it should work on other Debian and Red Hat distributions.

### One-time Installation

- The application server in this repository has been written in golang ([GO 1.7.1](https://golang.org/doc/go1.7)).
	It is likely that installing GO using the package management software (yum or apt-get....) may not install
	GO version 1.7.1. The following procedure will ensure that GO 1.7.1 will be installed.

	```sh
	# cd $HOME
	# wget https://storage.googleapis.com/golang/go1.7.1.linux-amd64.tar.gz
	# tar -C /usr/local -xzf ./go1.7.1.linux-amd64.tar.gz
	```
	
- Add the following environment variable to the profile (either **.bash_profile** or **.profile** located in $HOME directory.	
	
	```sh
	# echo 'export PATH=/usr/local/go/bin:/usr/local/bin:$PATH' >> ~/.profile
	OR
	# echo 'export PATH=/usr/local/go/bin:/usr/local/bin:$PATH' >> ~/.bash_profile
	```

### Application path

-	Assuming that the application will be installed (using git or svn) in $HOME, add the following environment
	variables to the profile (either **.bash_profile** or **.profile** located in $HOME directory.

	For example,
 
	```sh
	# cd $HOME
	# svn checkout https://github.com/comcast/vesper/trunk vesper
	```

- Add the **GOPATH** and **GOBIN** environment variables to the profile (either **.bash_profile** or **.profile** 
	located in $HOME directory.	
	
	```sh
	# echo 'export GOPATH=$HOME/vesper' >> ~/.profile
	# echo 'export GOBIN=$GOPATH/bin' >> ~/.profile
	
	OR
	
	# echo 'export GOPATH=$HOME/vesper' >> ~/.bash_profile
	# echo 'export GOBIN=$GOPATH/bin' >> ~/.bash_profile
	```

## Compiling the application

This [link](https://golang.org/cmd/go/) explains how to use the **go** tool. Since the environment variables **GOPATH**
and **GOBIN** are already set, the **go** tool can be run **from anywhere**.

- To compile and install the application (in GOBIN) with one command run

	```sh
	# go install app_server
	```

## Configuration
At startup, the application expects to read a JSON object in a configuration file. The following are the keysthat can be present
in the JSON object

### log_file
This is file that vesper logs information. Typically, the value contains the ABSOLUTE PATH (to avoid confusion) followed 
by the log file name

### fqdn
This is the IP address or domain name of the host on which vesper is running. The fqdn appears in every line in the log file

### ssl_cert_file
If vesper is to run as a HTTPs server, the server MUST be reachable via a FQDN and MUST also have valid X.509 certificate and key file

### ssl_key_file
Private key file associated to the certificate used to run vesper as a HTTPs server

### compact
When signing the JWS, this boolean determines whether the SIP Identity header must also include the header and claims.

### authentication

#### x5u
This is the URL which contains the path to the cert file which will be required to verify the signature created using the
elliptic curve based private key

#### pvt_key_file
This file contains the elliptic curve based private key in PEM format. This key is used to sign the JWS in the SIP Identity header.
 
- Example

```sh
{
	"log_file" : "/var/log/app_server/app_server.log",
	"fqdn" : "",
	"ssl_cert_file" : "",
	"ssl_key_file" : "",
	"compact" : false,
	"authentication" : {
		"x5u" : "",
		"pvt_key_file" : ""
	}
}
```

## Running the application

The executable is installed in GOBIN. The application expects to read a JSON object in a configuration file. Typically,
the configuration file will reside in GOPATH/config directory. An example for running the application would look
like this

```sh
# $HOME/vesper/bin/app_server $HOME/vesper/config/config.json
```
 
## References

- [Authenticated Identity Management in the Session Initiation Protocol](https://tools.ietf.org/html/draft-ietf-stir-rfc4474bis-10)
- [Persona Assertion Token](https://tools.ietf.org/html/draft-ietf-stir-passport-05)

###License and Copyright

Licensed under the Apache License, Version 2.0

Copyright 2016 Comcast Cable Communications Management, LLC

This product includes software developed at Comcast (http://www.comcast.com/).

Cocktail Shaker by Sergey Demushkin from the Noun Project

Cocktail by Dominique Vicent from the Noun Project