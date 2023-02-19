package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

const (
	snapshotModuleHikvisionNonceExpirationSpoof = "hikvision_spoof_nonce_expiration"
	oneYear = time.Hour * 24 * 365 * 10
)
var isAllDigitsRe = regexp.MustCompile("^[0-9]+$")
var httpTransportsByTimeout = make(map[uint]http.RoundTripper)

func HttpTransportWithTimeout(timeout uint) http.RoundTripper {
	if timeout > 0 {
		if transport, ok := httpTransportsByTimeout[timeout]; ok {
			return transport
		}

		dialer := &net.Dialer{
			Timeout: time.Duration(timeout) * time.Second,
		}

		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
		}

		httpTransportsByTimeout[timeout] = transport
		return transport
	}

	return http.DefaultTransport
}

func (s *SnapshotST) LoadModules() {
	if s.Modules == nil {
		return
	}

	for _, module := range s.Modules {
		switch module {
		case snapshotModuleHikvisionNonceExpirationSpoof:
			// Hikvision nonces are in the form of `<hash>:<unix_ts>`. The timestamp is not embedded
			// into the hash whatsoever, so we can just spoof its expiration :-)
			if !s.DigestAuth.Enabled || !s.DigestAuth.AllowNonceReuse {
				return
			}

			s.DigestAuth.requestor.Hooks.BeforePersistState = func(c context.Context, state *DigestAuthState) {
				// assume already generated states are already patched
				if !state.IsFresh() {
					return
				}
				// note: potential for races here between the get and set, but it's not really that
				// relevant as all nonces keep being valid, we just alter the timestamp.
				nonce, expiration, found := strings.Cut(state.Get("nonce"), ":")

				if !found || !isAllDigitsRe.MatchString(expiration) {
					if logger, ok := c.Value("logger").(*logrus.Entry); ok {
						logger.Warnf(
							"Module '%v' is registered for snapshot config, but incompatible nonce was found",
							snapshotModuleHikvisionNonceExpirationSpoof,
						)
					}
					return
				}

				expiration = strconv.FormatInt(time.Now().Add(oneYear).UnixMilli(), 10)
				state.Set("nonce", fmt.Sprintf("%v:%v", nonce, expiration))
			}
		default:
			log.Fatalf("unknown module in snapshot configuration: %v", module)
		}
	}
}

func (s *SnapshotST) RequestSnapshot(c context.Context) (*http.Response, error) {
	// Determine auth type.
	if !s.DigestAuth.Enabled {
		// fast path
		return s.client.Get(s.URL)
	}

	uri, err := url.Parse(s.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to create URL: %w", err)
	}

	res, err := s.DigestAuth.requestor.Request(c, *uri)

	if errors.Is(err, ErrDigestAuthMissingCredentials) {
		// no credentials in URL, assume this was by mistake
		if logger, ok := c.Value("logger").(*logrus.Entry); ok {
			logger.Logger.Warnf(
				"attempted to use digest auth authenticator with URL with no credentials in it: %v",
				s.URL,
			)
		}
		return s.client.Get(s.URL)
	}

	return res, err
}

func HTTPAPIServerProduceSnapshot(c *gin.Context) {
	logger := log.WithFields(logrus.Fields{
		"module":  "http_snapshot",
		"stream":  c.Param("uuid"),
		"channel": c.Param("channel"),
		"func":    "HTTPAPIServerProduceSnapshot",
	})

	if !Storage.StreamChannelExist(c.Param("uuid"), c.Param("channel")) {
		c.IndentedJSON(500, Message{Status: 0, Payload: ErrorStreamNotFound.Error()})
		return
	}

	channel, err := Storage.StreamChannelInfo(c.Param("uuid"), c.Param("channel"))

	if err != nil {
		c.AbortWithError(500, err)
		return
	}

	if channel.Snapshot.URL == "" {
		c.JSON(500, Message{Status: 0, Payload: ErrorStreamChannelSnapshotDisabled.Error()})
		return
	}

	cfg := channel.Snapshot
	res, err := cfg.RequestSnapshot(context.WithValue(c, "logger", logger))
	if err != nil {
		logger.Errorf("request to camera failed: %v", err)
		c.JSON(500, Message{Status: 0, Payload: "request to camera failed"})
		return
	}

	defer res.Body.Close()
	io.Copy(c.Writer, res.Body)
}
