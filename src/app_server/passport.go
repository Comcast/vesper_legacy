// Copyright 2016 Comcast Cable Communications Management, LLC

package main

import (
	"fmt"
	"crypto"
	"crypto/rsa"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"encoding/base64"
	"strings"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

// Encoding 
// signer returns a signature for the given data.
type signer func(data []byte) (sig []byte, err error)

// EncodeWithSigner encodes a header and claim set with the provided signer.
func encodeWithSigner(header *string, claims *string, sg signer) (string, error) {
	h := base64Encode([]byte(*header))
	c := base64Encode([]byte(*claims))
	ss := fmt.Sprintf("%s.%s", h, c)
	sig, err := sg([]byte(ss))
	if err != nil {
		return "", err
	}
	// return the signature part of JWT ONLY
	return fmt.Sprintf("%s", base64Encode(sig)), nil
}

// Encode encodes a signed JWS with provided header and claim set.
// This invokes EncodeWithSigner using crypto/rsa.SignPKCS1v15 with the given RSA private key.
func encodeRsa(header *string, claims *string, key *rsa.PrivateKey) (string, error) {
	sg := func(data []byte) (sig []byte, err error) {
		h := sha256.New()
		h.Write([]byte(data))
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h.Sum(nil))
	}
	return encodeWithSigner(header, claims, sg)
}

// Encode encodes a signed JWS with provided header and claim set.
// This invokes EncodeWithSigner using crypto/ecdsa.Sign with the given EC private key.
// If only the signature component of PASSPORT is required, the boolean canon MUST be false
func encodeEC(header *string, claims *string, key *ecdsa.PrivateKey) (string, error) {
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

func verifyRsa(token string, key *rsa.PublicKey) error { 
	ver := func(data []byte, signature []byte) (err error) { 
		h := sha256.New() 
		h.Write([]byte(data)) 
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, h.Sum(nil), signature) 
	} 
	return verifyWithSigner(token, ver) 
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

// create_signature is called to create a JWT using either RS256 or ES256 
// algorithm.
// Note: The header and claims part of the created JWT is stripped out
//			 before returning the signature only
func create_signature(header, claims, alg string) (string, error)  {
	logInfo(header)
	logInfo(claims)
	
	private_key_file := Config.Authentication["private_key_file"].(string)
	// decode the private key
	pvtkeybyte, err := ioutil.ReadFile(private_key_file)
	if err == nil {
		decodedPEM, _ := pem.Decode(pvtkeybyte)
		if decodedPEM != nil {
			switch (alg) {
			case "RS256":
				// alg = RS256
				pvtkey, err := x509.ParsePKCS1PrivateKey(decodedPEM.Bytes)
				if err == nil {
					sig, err := encodeRsa(&header, &claims, pvtkey)
					if err == nil {
						logInfo("%v", sig)
						return sig, nil		
					}
				}
			default : 
				// alg = ES256
				pvtkey, err := x509.ParseECPrivateKey(decodedPEM.Bytes)
				if err == nil {
					sig, err := encodeEC(&header, &claims, pvtkey)
					if err == nil {
						return sig, nil
					}
				}		
			}
		} else {
			err = fmt.Errorf("no PEM data found")
		}		
	}
	// Handle error condition for any error here	
	logError("err: %v", err)
	return "", err
}

// verify_signature is called to verify the signature which was created 
// using either RS256 or ES256 algorithm.
// If the signature ois verified, the function returns nil. Otherwise,
// an error message is returned
func verify_signature(header, claims, signature, alg string) error {
	logInfo(header)
	logInfo(claims)

	public_key_file := Config.Verification["vesper"].(string)
	pubkeybyte, err := ioutil.ReadFile(public_key_file)
	if err == nil {
		decodedPEM, _ := pem.Decode(pubkeybyte)
		if decodedPEM != nil {
			pub, err := x509.ParsePKIXPublicKey(decodedPEM.Bytes)
			if err != nil {
				logError("Failed to parse RSA public key: %s", err)
				return err
			}
			h := base64Encode([]byte(header))
			c := base64Encode([]byte(claims))
			token := fmt.Sprintf("%s.%s.%s", h, c, signature)
			//logError("token %v", token)
			if alg == "RS256" {			
				rsaPub, ok := pub.(*rsa.PublicKey)
				if !ok {        
					err = fmt.Errorf("Value returned from ParsePKIXPublicKey was not an RSA public key")
					return err
				}
				return verifyRsa(token, rsaPub)
			}
			// ES256
			ecdsaPub, ok := pub.(*ecdsa.PublicKey)
			if !ok {        
				err = fmt.Errorf("Value returned from ParsePKIXPublicKey was not an ECDSA public key")
				return err
			}
			return verifyEC(token, ecdsaPub)
		}
	}
	return err
}