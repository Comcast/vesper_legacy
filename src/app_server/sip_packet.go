// Copyright 2016 Comcast Cable Communications Management, LLC

package main

import (
	"net/http"
	"github.com/httprouter"
	"time"
	"io/ioutil"
	"regexp"
	"strings"
	"fmt"
	"strconv"
)

// process_sip_message parses the SIP message in the HTTP body in accordance
// https://tools.ietf.org/html/draft-ietf-stir-rfc4474bis-08
// Note: At this point in time
//  1. full coverage of the draft is not implemented.
//  2. syntax validation is not comprehensive 
func process_sip_message(response http.ResponseWriter, request *http.Request, _ httprouter.Params) {
	start := time.Now()
	client_ip := request.Header.Get("X-Real-IP")
	if request.Method != "POST" {
		if client_ip != "" {
			logError("received %s request instead of \"PUT\" request from %s", request.Method, client_ip);
		}
 		response.WriteHeader(http.StatusBadRequest)
 		response.Write([]byte("Only POST request is supported for this API"))
		return
	}
	content_type := request.Header.Get("Content-Type")
	logInfo("content type is " + content_type);
		
	buff, _ := ioutil.ReadAll(request.Body)
	//logInfo("%#v ", buff)
	//buff := bytes.NewBuffer(body)
	
	// 1. convert bytes to string and trim leading and trailing white spaces
	sip_payload := strings.TrimSpace(string(buff[:]))
	logInfo("sip payload : ", sip_payload);
	//total_length := len(buff)
	
	// 2. Get the Request/Response line
	index := strings.Index(sip_payload, "\r\n")
	if index == -1 {
		logError("Invalid request - either not an INVITE or other error when attempting to read request-line")
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("Invalid request - either not an INVITE or other error when attempting to read request-line"))
		return
	}
	
	// 3. verify Request is INVITE
	if !is_sip_invite(sip_payload[:index]) {
			logError("Not a SIP INVITE");
			response.WriteHeader(http.StatusBadRequest)
			response.Write([]byte("Not a SIP INVITE"))
			return
	}
	
	var jwt_claims Jwt_claims

	// 4. extract all headers.
	header_start_index := index + 2	// points to the first SIP header
	index = strings.Index(sip_payload[header_start_index:], "\r\n\r\n")
	if index == -1 {
		logError("No separator \\r\\n\\r\\n found")
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("No separator \\r\\n\\r\\n found"))
		return
	}
	
	// constructing the new payload to be sent in response body
	// copy the INVITE request line to new payload to be sent as response
	// Will be using string concatenation to construct the new SIP payload
	// Although  string concatenation is not the fastest, in this case
	// it seems to be comparable with other faster methods such as 
	// byte sclie appending or bytebyffer appending
	// http://golang-examples.tumblr.com/post/86169510884/fastest-string-contatenation	
	new_payload := sip_payload[:header_start_index]	

	// 5. get all headers. index is an offset from  header_start_index and NOT from the beginning of the SIP payload 
	hdrs := strings.Split(sip_payload[header_start_index:header_start_index+index], "\r\n")

	// 6. declare variables that serves in claims and header
	var from, to, sig, x5u, canonical_string, content_length string
	date_header := false
	identity_header := false
	alg := "ES256"	// default
	// 7. iterate the SIP headers to find the following headers and extract information
	//	1. Identity
	//	2. From
	//	3. To
	//	4. Date
	//	5. Content-Length 
	for i := range hdrs {
		logInfo("hdrs[%d] : %s", i, hdrs[i]);
		sp := strings.IndexRune(hdrs[i], ':')
		if sp == -1 {
			logError("no semi found in header")
			response.WriteHeader(http.StatusBadRequest)
			response.Write([]byte("no semi found in header"))
			return
		}

		hdr := strings.ToLower(strings.TrimSpace(hdrs[i][0:sp]))
		switch hdr {
		case "identity":
			// 1. If "Identity" header is present, do not add that header to the new payload
			//		as it must be removed in new SIP payload response 
			//		verify signature here
			identity_header = true
			id := strings.TrimSpace(hdrs[i][sp+1:])
			end_of_sig := strings.Index(id, ";")
			if end_of_sig == -1  {
				logError("no parameters after signature")
				response.WriteHeader(http.StatusBadRequest)
				response.Write([]byte("no parameters after signature"))
				return
			}
			sig = id[:end_of_sig]
			// logInfo("Signature only : %s", id[:end_of_sig])
	
			// 2. Start from the offset that indicates the end of signature
			//		in the Identity header. Note: The parameters can be in any order after the
			//		signature.
			// 2.1. Get x5u value from info parameter, if present
			info := id[end_of_sig:]
			x5u_start := strings.Index(info[:], ";info=<")
			if x5u_start == -1 {
				logError("no x5u info after signature")
				response.WriteHeader(http.StatusBadRequest)
				response.Write([]byte("no x5u info after signature"))
				return
			}
			// offset to the start of the URI in info parameter
			info = info[x5u_start+7:]
			x5u_end := strings.Index(info[:], ">")
			if x5u_end == -1 {
				logError("unable to extract x5u info")
				response.WriteHeader(http.StatusBadRequest)
				response.Write([]byte("unable to extract x5u info"))
				return
			}
			x5u = info[:x5u_end]
								
			// 2.2. get "alg" if alg parameter present. Go back offset that indicates the 
			//	end of signature in the Identity header
			alg_info := id[end_of_sig:]
			alg_start := strings.Index(alg_info[:], ";alg=")
			if alg_start > -1 {
				// offset to the start of the alg value in alg parameter
				alg_info = alg_info[alg_start+5:]
				alg_end := strings.Index(alg_info[:], ";")
				if alg_end == -1 {
					// Assume that this is the last parameter and hence ";" does not exist
					// at the end
					alg = alg_info[:]
				} else {
					alg = alg_info[:alg_end]
				}
				// If alg is not ES256 return error
				if alg != "ES256" {
					logError("Invalid algorithm in Identity header")
					response.WriteHeader(http.StatusBadRequest)
					response.Write([]byte("Invalid algorithm in Identity header"))
					return
				}
			} 
			// else
      // "alg" parameter is absent from the Identity header, the default
      // value is "ES256" - section 4.1 in https://tools.ietf.org/html/draft-ietf-stir-rfc4474bis-12
			
			// 2.3 check if canonical string is present
			canon_str := id[end_of_sig:]
			canon_start := strings.Index(canon_str[:], ";canon=")
			if canon_start == -1 {
				// no canonical string found
			} else {
				// JWT header and claims is assumed present. Validate
				// offset to the start of the alg value in alg parameter
				canon_str = canon_str[canon_start+7:]
				canon_end := strings.Index(canon_str[:], ";")
				if canon_end == -1 {
					// Assume that this is the last parameter and hence ";" does not exist
					// at the end
					canonical_string = canon_str[:]
				} else {
					canonical_string = canon_str[:canon_end]
				}			
			}		
		case "to":
			// get telnumber from "To" and "From" header
			var is_tel bool
			var err error
			to, is_tel, err = get_tn_or_uri(strings.TrimSpace(hdrs[i][sp+1:]))
			if err != nil {
				logError("Issue parsing \"to\" header : %v", err)
				response.WriteHeader(http.StatusBadRequest)
				response.Write([]byte(err.Error()))
				return
			}
			// "dtn" or "duri"
			if is_tel {
				jwt_claims.Dest = map[string]interface{}{"tn":[]string{to}}
			} else {
				jwt_claims.Dest = map[string]interface{}{"uri":[]string{to}}
			}
			
			// append header to payload to be sent as response
			new_payload = new_payload + hdrs[i] + "\r\n"			
		case "from":
			var is_tel bool
			var err error
			// get telnumber from "To" and "From" header
			from, is_tel, err = get_tn_or_uri(strings.TrimSpace(hdrs[i][sp+1:]))
			if err != nil {
				logError("Issue parsing \"from\" header : %v", err)
				response.WriteHeader(http.StatusBadRequest)
				response.Write([]byte(err.Error()))
				return
			}
			// "otn" or "ouri"
			if is_tel {
				jwt_claims.Orig = map[string]interface{}{"tn": string(from)}
			} else {
				jwt_claims.Orig = map[string]interface{}{"uri": string(from)}
			}

			// append header to payload to be sent as response
			new_payload = new_payload + hdrs[i] + "\r\n"			
		case "date":
			// get date from "Date" header
			d := strings.TrimSpace(hdrs[i][sp+1:])
			var t time.Time
			t, err := time.Parse(time.RFC1123, d)
			if err != nil {
				logError("Issue parsing \"Date\" header : %v", err)
				response.WriteHeader(http.StatusBadRequest)
				response.Write([]byte(err.Error()))
				return
			}
			jwt_claims.Iat = t.Unix()
			date_header = true
			
			// append header to payload to be sent as response
			new_payload = new_payload + hdrs[i] + "\r\n"
		case "content-length":
			content_length = hdrs[i] + "\r\n"
		default:
			// append header to payload to be sent as response
			new_payload = new_payload + hdrs[i] + "\r\n"
		}
	}
		
	// 7. pscTo is either otn or ouri. Likewise, pscFrom is either dtn or duri
	if len(to) <= 0 || len(from) <= 0 {
		logError("Unable to determine otn/ouri OR dtn/duri")
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("Unable to determine otn/ouri OR dtn/duri"))
		return
	}
	
	// 8. Identity header not found - add signature
	if !identity_header {
		// if "Date" header is not found, we generate the JWS issued at time only
		if !date_header {
			jwt_claims.Iat = start.Unix()	// for claims
			// Adding Date header
			new_payload = new_payload + "Date: " + strings.Replace(start.Format(time.RFC1123), "UTC", "GMT", -1) + "\r\n"
		}	
		logInfo("\"Identity\" header not in SIP payload")		
		// Initialize JWT header 
		jwt_header := Jwt_header{"ES256", "passport", Config.Authentication["x5u"].(string)}
		logInfo("%v", jwt_header)
		logInfo("%v", jwt_claims)
		// Adding "Identity" header as the last header in the new SIP payload
		canonical_string, sig, err := create_signature(&jwt_header, &jwt_claims)
		if err != nil {
			logError("Issue creating JWS : %v", err)
			response.WriteHeader(http.StatusBadRequest)
			response.Write([]byte(err.Error()))
			return
		}
		if Config.Canon {
			new_payload = new_payload + "Identity: " + sig + ";info=<" + Config.Authentication["x5u"].(string)  + ">;alg=ES256;canon="  + canonical_string + "\r\n"
		} else {
			new_payload = new_payload + "Identity: " + sig + ";info=<" + Config.Authentication["x5u"].(string)  + ">;alg=ES256\r\n"
		}
		// Append Content-Length as the last header before message body
		new_payload = new_payload + content_length
		response.WriteHeader(http.StatusOK)
	} else {
		// identity header found
		if !date_header && len(canonical_string) == 0 {
			// Date Header not found. If the Identity header exists, the Date header MUST also exist
			logError("Date header not present")
			response.WriteHeader(http.StatusForbidden)
			response.Write([]byte("Date header not present"))
			return
		}	
		// if canonical string does not exist, create header and claims
		var jwt string
		if len(canonical_string) == 0 {
			// construct JWT header 
			jwt_header := Jwt_header{alg, "passport", x5u}
			h, err := jwt_header.encode()
			if err != nil {
				logError("%v", err)
				response.WriteHeader(http.StatusForbidden)
				response.Write([]byte(err.Error()))
				return
			}
			c, err := jwt_claims.encode()
			if err != nil {
				logError("%v", err)
				response.WriteHeader(http.StatusForbidden)
				response.Write([]byte(err.Error()))
				return
			}
			jwt = fmt.Sprintf("%s.%s.%s", h, c, sig)			
		} else {
			jwt = fmt.Sprintf("%s.%s", canonical_string, sig)
		}
		// new_payload contains a copy of the incoming SIP payload upto the last header except
		// for the "Identity" header
		err := verify_signature(x5u, jwt)
		if err != nil {
			logError("%v", err)
			response.WriteHeader(http.StatusForbidden)
			response.Write([]byte(err.Error()))
			return
		}
		// Append Content-Length as the last header before message body
		new_payload = new_payload + content_length		
		response.WriteHeader(http.StatusOK)
	}
	// 9. Append CRLF + SIP message body if present
	new_payload = new_payload + "\r\n" + sip_payload[header_start_index+index+4:] + "\r\n"
	//logInfo("%#v", []byte(new_payload))
	logInfo("%v", new_payload)	

	response.Header().Set("Content-Length", strconv.Itoa(len(new_payload)))
	response.Header().Set("Content-Type", content_type)	// same as request
	response.Write([]byte(new_payload))
	logInfo("Response time : %v", time.Since(start));
}

func is_sip_invite(str string) bool  {
	r, _ := regexp.Compile(`^INVITE`)
	return r.MatchString(str)
}

func is_tel_no(str string) bool  {
	r, _ := regexp.Compile(`^\+?([0-9-.]+)$`)
	return r.MatchString(str)
}

// get_tn_or_uri parses From and To header
// Conforms to section 8.1 (Differentiating Telephone Numbers from URIs) 
// in https://tools.ietf.org/html/draft-ietf-stir-rfc4474bis-12
func get_tn_or_uri(header_text string) (psc string, is_tel bool, err error) {
	is_tel = false
	if len(header_text) == 0 {
		err = fmt.Errorf("address-type header has empty body")
		return
	}
	
	header_text_copy := header_text
	header_text = strings.TrimSpace(header_text)
	display_name_present := false
	// There is a display name present. Let's parse it.
	if header_text[0] == '"' {    
		display_name_present = true 		
		// The display name is within quotations.
		header_text = header_text[1:]
		next_quote := strings.Index(header_text, "\"")
		if next_quote == -1 {
			// Unclosed quotes - parse error.
			err = fmt.Errorf("Unclosed quotes in header text: %s", header_text_copy)
			return
		}
		header_text = header_text[next_quote+1:]
	} else {
		// else display name, if present, is unquoted
		index_after_display_name := strings.Index(header_text, "<")
		if index_after_display_name > -1 {
			header_text = header_text[index_after_display_name:]
		} // else no display name with or without quote
	}
	
	// Work out where the SIP/TEL URI starts and ends.
	header_text = strings.TrimSpace(header_text)
	var end_of_uri int
	if header_text[0] != '<' {
		if display_name_present {
			// The address must be in <angle brackets> if a display name is
			// present, so this is an invalid address line.
			err = fmt.Errorf("Invalid character '%c' following display "+
				"name in address line; expected '<': %s",
				header_text[0], header_text_copy)
			return
		}	
		end_of_uri = strings.Index(header_text, ";")
		if end_of_uri == -1 {
			end_of_uri = len(header_text)
		}
	} else {
		header_text = header_text[1:]
		end_of_uri = strings.Index(header_text, ">")
		if end_of_uri == -1 {
			err = fmt.Errorf("'<' without closing '>' in address %s", header_text_copy)
			return
		}
	}
	
	// Now parse the SIP URI.
	header_text = header_text[:end_of_uri]
	if strings.TrimSpace(header_text) == "*" {
		// Wildcard '*' URI used in the Contact headers of REGISTERs when unregistering.
		err = fmt.Errorf("Invalid URI %s", header_text)
		return
	}

	colon_index := strings.Index(header_text, ":")
	if colon_index == -1 {
		err = fmt.Errorf("no ':' in URI %s", header_text)
		return
	}

	is_sips := false
	is_tel = false
	switch strings.ToLower(header_text[:colon_index]) {
	case "sip":
		header_text = header_text[3:]
	case "tel":
		header_text = header_text[3:]
		is_tel = true
	case "sips":
		header_text = header_text[4:]
		is_sips = true
	default:
		err = fmt.Errorf("Unsupported URI schema %s", header_text[:colon_index])
	}
	// 'tel' or 'sip' or 'sips' protocol name should be followed by a ':' character.
	if header_text[0] != ':' {
		err = fmt.Errorf("no ':' after protocol name in SIP uri '%s'", header_text)
		return
	}
	// go to the beginning of the uri
	header_text = header_text[1:]
	
	// This could be of the format
	// 1. tel num\r\n
	// 2. tel num>\r\n
	// 3. tel num@domain\r\n
	// 4. tel num@domain>\r\n
	// 5. tel num@domain;...\r\n
	// 6. name@domain\r\n
	// 7. name@domain>\r\n
	// 8. name@domain;...\r\n
	end_of_user_info_part := strings.Index(header_text, "@")
	if end_of_user_info_part == -1 {
		// Assume this is a SIP URI
		end_of_user_info_part = len(header_text)
	}
	// Check if tel number
	if is_tel_no(header_text[:end_of_user_info_part]) {
		psc = header_text[:end_of_user_info_part]
		is_tel = true
		err = nil
		return
	} else {
		if is_tel {
			err = fmt.Errorf("Invalid tel format :'%s'", header_text)
			return
		} else {
			if is_sips {
				psc = "sips:" + header_text
			} else {
				psc = "sip:" + header_text
			}
			is_tel = false
			err = nil
			return
		}
	}
}
