// Copyright 2016 Comcast Cable Communications Management, LLC

package main

import (
	"fmt"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"encoding/base64"
	"strings"
	"crypto/x509"
	"encoding/pem"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

// structure that holds JWT header
type Jwt_header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Ppt string `json:"ppt"`
	X5u string `json:"x5u"`
}

// structure that holds JWT claims
type Jwt_claims struct {
	Attest   string  `json:"attest"`
	Dest  map[string]interface{} `json:"dest"`   // unmarshals a JSON object into a string-keyed map
	Iat   string  `json:"iat"`
	Orig  map[string]interface{} `json:"orig"`   // unmarshals a JSON object into a string-keyed map
	Origid   string  `json:"origid"`
}

// base64Encode returns and Base64url encoded version of the input string with any
// trailing "=" stripped.
func base64Encode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// ---------------------------------------------------

// Decoding
// Decode JWT specific base64url encoding with padding stripped
func base64Decode(sig string) ([]byte, error) {
	// add back missing padding
	switch len(sig) % 4 {
	case 1:
		sig += "==="
	case 2:
		sig += "=="
	case 3:
		sig += "="
	}
	return base64.URLEncoding.DecodeString(sig)
}

// base64 encode header
func (h *Jwt_header) encode() (string, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	str := string(b)
	Info.Println(str)
	return base64Encode(b), nil
}

// base64 encode claims
func (h *Jwt_claims) encode() (string, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	str := string(b)
	Info.Println(str)
	return base64Encode(b), nil
}

// Encoding 
// signer returns a signature for the given data.
type signer func(data []byte) (sig []byte, err error)

// EncodeWithSigner encodes a header and claim set with the provided signer.
func encodeWithSigner(header *Jwt_header, claims *Jwt_claims, sg signer) (string, string, error) {
	h, err := header.encode()
	if err != nil {
		return "", "", err
	}
	c, err := claims.encode()
	if err != nil {
		return "", "", err
	}
	ss := fmt.Sprintf("%s.%s", h, c)
	logInfo("%v", ss)
	sig, err := sg([]byte(ss))
	if err != nil {
		return "", "", err
	}
	// return the header and claims as one string, signature part of JWT and error value
	return ss, fmt.Sprintf("%s", base64Encode(sig)), nil
}

// Encode encodes a signed JWS with provided header and claim set.
// This invokes EncodeWithSigner using crypto/ecdsa.Sign with the given EC private key.
// If only the signature component of PASSPORT is required, the boolean canon MUST be false
func encodeEC(header *Jwt_header, claims *Jwt_claims, key *ecdsa.PrivateKey) (string, string, error) {
	sg := func(data []byte) (sig []byte, err error) {
		h := sha256.New()
		r := big.NewInt(0)
		s := big.NewInt(0)
		h.Write([]byte(data))
		r,s,err = ecdsa.Sign(rand.Reader, key, h.Sum(nil))
		signature := r.Bytes()
 		signature = append(signature, s.Bytes()...)
		return signature, err
	}
	return encodeWithSigner(header, claims, sg)
}

type Verifier func(data []byte, signature []byte) (err error) 

func verifyWithSigner(token string, ver Verifier) error { 
	parts := strings.Split(token, ".") 
	signedPart := []byte(strings.Join(parts[0:2], ".")) 
	signatureString, err := base64Decode(parts[2]) 
	if err != nil { 
		return err 
	}
	return ver(signedPart, []byte(signatureString)) 
} 

func verifyEC(token string, key *ecdsa.PublicKey) error { 
	ver := func(data []byte, signature []byte) (err error) { 
		h := sha256.New()
		r := big.NewInt(0)
		s := big.NewInt(0)
		h.Write([]byte(data))
		r = new(big.Int).SetBytes(signature[:len(signature)/2])
		s = new(big.Int).SetBytes(signature[len(signature)/2:])
		if ecdsa.Verify(key, h.Sum(nil), r, s) {
			return nil
		}
		return fmt.Errorf("Unable to verify ES256 signature") 
	} 
	return verifyWithSigner(token, ver)
}


//------------------------------------------------------------------
// create_signature is called to create a JWT using ES256 algorithm.
// Note: The header and claims part of the created JWT is stripped out
//			 before returning the signature only
func create_signature(header *Jwt_header, claims *Jwt_claims) (string, string, error)  {	
	private_key_file := Config.Authentication["pvt_key_file"].(string)
	// decode the private key
	pvtkeybyte, err := ioutil.ReadFile(private_key_file)
	if err == nil {
		block, _ := pem.Decode(pvtkeybyte)
		if block != nil {
			// alg = ES256
			pvtkey, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				logInfo("Got here")
				canonical_string, sig, err := encodeEC(header, claims, pvtkey)
				if err == nil {
					return canonical_string, sig, nil
				}
			} else {
				logInfo("%v", err)
			}
		} else {
			err = fmt.Errorf("no PEM data found")
		}		
	}
	// Handle error condition for any error here	
	logError("err: %v", err)
	return "", "", err
}

// verify_signature is called to verify the signature which was created 
// using  ES256 algorithm.
// If the signature ois verified, the function returns nil. Otherwise,
// an error message is returned
func verify_signature(x5u, token string) error {
	// Get the data each time
	resp, err := http.Get(x5u)
	if err != nil {
		logError("%v", err)
		return err
	}
	defer resp.Body.Close()
	// Writer the body to buffer
	cert_buffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logError("%v", err)
		return err
	}
	block, _ := pem.Decode(cert_buffer)
	if block == nil {
		err = fmt.Errorf("no PEM data is found")
		return err
	}	
	// parse certificate		
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	// ES256
	ecdsa_pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {        
		err = fmt.Errorf("Value returned from ParsePKIXPublicKey was not an ECDSA public key")
		return err
	}
	return verifyEC(token, ecdsa_pub)
}
