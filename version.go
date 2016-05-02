// Copyright 2016 Comcast Cable Communications Management, LLC

package main

import (
	"net/http"
	"encoding/json"
	"github.com/julienschmidt/httprouter"
)

const software_version = `STIR Appication Server 1.0.0`

type VersionQueryResponse struct {
	Version string
}

func version(response http.ResponseWriter, request *http.Request, _ httprouter.Params) {

	var json_resp VersionQueryResponse
	json_resp.Version = software_version
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	json.NewEncoder(response).Encode(json_resp)
}
