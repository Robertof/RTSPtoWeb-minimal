package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RFC 7616

const (
	digestAuthParamAlgorithm = "algorithm"
	digestAuthParamClientNonce = "cnonce"
	digestAuthParamNonce = "nonce"
	digestAuthParamNonceCount = "nc"
	digestAuthParamQop = "qop"
	digestAuthParamRealm = "realm"
	digestAuthParamResponse = "response"
	digestAuthParamUri = "uri"
	digestAuthParamUsername = "username"

	digestAuthAlgoUnspecified = ""
	digestAuthAlgoMd5 = "md5"
	digestAuthAlgoMd5Sess = "md5-sess"

	digestAuthQopUnspecified = ""
	digestAuthQopAuth = "auth"
	digestAuthQopAuthInt = "auth-int"
)

type DigestAuthState struct {
	mu sync.Mutex

	params map[string]string
	nonceCount int
	createdAt time.Time
}

func newDigestAuthStateFromChallenge(challenge string) (*DigestAuthState, error) {
	params, err := parseWWWAuthenticate(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to parse challenge from WWW-Authenticate header: %w", err)
	}

	return &DigestAuthState{
		params: params,
		createdAt: time.Now(),
	}, nil
}

func (s *DigestAuthState) IsFresh() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.nonceCount == 1
}

func (s *DigestAuthState) Get(param string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.params[param]
}

func (s *DigestAuthState) Set(param, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.params[param] = value
}

// Computes digest authentication response. Mutates the input state.
func (s *DigestAuthState) ComputeResponse(
	requestUri string,
	credentials *url.Userinfo,
) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nonceCount++ // make sure nonceCount is at least 1
	params := s.params
	rawNonceCount := s.nonceCount

	algo, qop, realm, nonce :=
		strings.ToLower(params[digestAuthParamAlgorithm]),
		strings.ToLower(params[digestAuthParamQop]),
		strings.ToLower(params[digestAuthParamRealm]),
		strings.ToLower(params[digestAuthParamNonce])

	nonceCount := fmt.Sprintf("%08x", rawNonceCount)
	pass, _ := credentials.Password()

	mkMd5 := func(input string) string {
		sum := md5.Sum([]byte(input))
		return hex.EncodeToString(sum[:])
	}

	var cnonce, ha1, ha2, response string

	// compute cnonce
	{
		buf := make([]byte, 16)
		_, err := rand.Read(buf)
		if err != nil {
			return "", fmt.Errorf("failed to fill cnonce: %w", err)
		}

		hash := md5.Sum(buf)
		cnonce = hex.EncodeToString(hash[:])
	}

	// compute ha1
	{
		if algo == digestAuthAlgoMd5 || algo == digestAuthAlgoMd5Sess || algo == digestAuthAlgoUnspecified {
			// HA1 = MD5(username:realm:password)
			ha1 = mkMd5(fmt.Sprintf("%v:%v:%v", credentials.Username(), realm, pass))
		} else {
			return "", fmt.Errorf("unknown algo: %v", algo)
		}

		if algo == digestAuthAlgoMd5Sess {
			// HA1 = MD5(MD5(username:realm:password):nonce:cnonce)
			ha1 = mkMd5(fmt.Sprintf("%v:%v:%v", ha1, nonce, cnonce))
			params[digestAuthParamClientNonce] = cnonce
		}
	}

	// compute ha2
	{
		if qop == digestAuthQopAuth || qop == digestAuthQopUnspecified {
			// HA2 = MD5(method:digestURI)
			ha2 = fmt.Sprintf("GET:%v", requestUri)
		} else if qop == digestAuthQopAuthInt {
			// HA2 = MD5(method:digestURI:MD5(entityBody))
			// assume entityBody is empty
			ha2 = fmt.Sprintf("GET:%v:d41d8cd98f00b204e9800998ecf8427e", requestUri)
		} else {
			return "", fmt.Errorf("unknown qop: %v", qop)
		}

		ha2 = mkMd5(ha2)
	}

	// compute response
	{
		if qop == digestAuthQopAuth || qop == digestAuthQopAuthInt {
			// response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)
			response = fmt.Sprintf("%v:%v:%v:%v:%v:%v", ha1, nonce, nonceCount, cnonce, qop, ha2)
			params[digestAuthParamClientNonce] = cnonce
		} else { // unspecified
			// response = MD5(HA1:nonce:HA2)
			response = fmt.Sprintf("%v:%v:%v", ha1, nonce, ha2)
		}

		sum := md5.Sum([]byte(response))
		response = hex.EncodeToString(sum[:])
	}

	params[digestAuthParamUsername] = credentials.Username()
	params[digestAuthParamNonceCount] = nonceCount
	params[digestAuthParamUri] = requestUri
	params[digestAuthParamResponse] = response

	var pieces []string

	for key, val := range params {
		val = strings.ReplaceAll(val, "\"", "\\\"")
		pieces = append(pieces, fmt.Sprintf("%v=\"%v\"", key, val))
	}

	return "Digest " + strings.Join(pieces, ", "), nil
}
