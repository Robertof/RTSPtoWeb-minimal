package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type DigestAuthNonceReusePolicy struct {
	canReuse func(*url.URL, *DigestAuthState) bool
}

var (
	ErrDigestAuthMissingCredentials = errors.New("credentials to perform digest authentication are missing")
	DigestAuthNonceReuseAlways = DigestAuthNonceReusePolicy{func(u *url.URL, das *DigestAuthState) bool {
		return true
	}}
	DigestAuthNonceReuseNever = DigestAuthNonceReusePolicy{func(u *url.URL, das *DigestAuthState) bool {
		return false
	}}
	perHostAuthStateCache sync.Map
)

func DigestAuthNonceReuseWithinTimeout(timeoutSeconds int) DigestAuthNonceReusePolicy {
	return DigestAuthNonceReusePolicy{func(u *url.URL, state *DigestAuthState) bool {
		deadline := state.createdAt.Add(time.Duration(timeoutSeconds) * time.Second)

		return time.Now().Before(deadline)
	}}
}

type DigestAuthRequestor struct {
	*http.Client
	EnablePerHostAuthStateCache bool
	NonceReusePolicy DigestAuthNonceReusePolicy
	Hooks struct {
		BeforePersistState func(context.Context, *DigestAuthState)
	}
}

func NewDigestAuthRequestor(client *http.Client) *DigestAuthRequestor {
	return &DigestAuthRequestor{
		Client: client,
		NonceReusePolicy: DigestAuthNonceReuseNever,
		EnablePerHostAuthStateCache: true,
	}
}

func challengeFromResponse(res *http.Response) (string, error) {
	auth := strings.TrimSpace(res.Header.Get("www-authenticate"))
	if res.StatusCode != http.StatusUnauthorized || auth == "" {
		// unexpected non-OK status, croak
		return "", fmt.Errorf("unexpected status (%v) or empty WWW-Authenticate header", res.Status)
	}

	return auth, nil
}

func (r *DigestAuthRequestor) retrieveChallenge(c context.Context, uri *url.URL) (string, *http.Response, error) {
	if uri.User != nil {
		panic("programmer error: DigestAuthRequestor.fetchAuthParams invoked with URL with credentials")
	}

	req, err := http.NewRequestWithContext(c, "GET", uri.String(), http.NoBody)
	if err != nil {
		return "", nil, fmt.Errorf("nonce mk request failed: %w", err)
	}
	res, err := r.Client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("nonce request failed: %w", err)
	}

	if res.StatusCode >= 200 && res.StatusCode <= 299 {
		// unexpected OK status, assume auth has been disabled
		return "", res, nil
	}

	io.Copy(io.Discard, res.Body)
	res.Body.Close()

	challenge, err := challengeFromResponse(res)
	return challenge, nil, err
}

func (r *DigestAuthRequestor) Request(c context.Context, origUri url.URL) (*http.Response, error) {
	if origUri.User == nil {
		// no user, assume no auth and option enabled in error.
		return nil, ErrDigestAuthMissingCredentials
	}

	// zero out user info from the original url to retrieve the auth info
	credentials := origUri.User
	noCredsUri := origUri
	noCredsUri.User = nil

	var state *DigestAuthState

	if r.EnablePerHostAuthStateCache {
		if loaded, ok := perHostAuthStateCache.Load(origUri.Host); ok {
			state = loaded.(*DigestAuthState)

			state.mu.Lock()
			canReuse := r.NonceReusePolicy.canReuse != nil && r.NonceReusePolicy.canReuse(&origUri, state)
			state.mu.Unlock()

			if !canReuse {
				perHostAuthStateCache.Delete(origUri.Host)
				state = nil
			}
		}
	}

	// base case, no previous state -- need to fetch challenge
	if state == nil {
		challenge, response, err := r.retrieveChallenge(c, &noCredsUri)

		if err != nil {
			return nil, err
		} else if challenge == "" {
			// no challenge = no auth
			return response, nil
		}

		state, err = newDigestAuthStateFromChallenge(challenge)

		if err != nil {
			return nil, fmt.Errorf("failed to create a new digest auth state: %w", err)
		}
	}

computeResponseAndFetch:
	digestResponse, err := state.ComputeResponse(noCredsUri.RequestURI(), credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to compute digest response: %w", err)
	}

	// final req
	req, err := http.NewRequestWithContext(c, "GET", noCredsUri.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("mk request failed: %w", err)
	}

	req.Header.Add("Authorization", digestResponse)

	res, err := r.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if !r.EnablePerHostAuthStateCache { // if the cache is disabled, no nonce reusing is possible
		goto end
	}

	// We might have received an unauthorized state if the reuse attempt failed. Restart from
	// scratch if this is the case.
	if res.StatusCode == http.StatusUnauthorized && !state.IsFresh() {
		res.Body.Close()

		if logger, ok := c.Value("logger").(*logrus.Entry); ok {
			logger.Warn(
				"digestAuth: state reuse attempt failed. If you see lots of these, you might want to " +
				"tweak `nonce_reuse_timeout` or your server might not support state reusing",
			)
		}

		perHostAuthStateCache.Delete(origUri.Host)

		// Attempt to get a new challenge from the response to avoid another roundtrip,
		// or start from scratch.
		if challenge, err := challengeFromResponse(res); err == nil {
			state, err = newDigestAuthStateFromChallenge(challenge)
			if err == nil {
				// note: no risk of infinite looping here, state.IsFresh() is true.
				goto computeResponseAndFetch
			}
		}

		// Failed to find a challenge, try again from scratch.
		return r.Request(c, origUri)
	} else if res.StatusCode >= 200 && res.StatusCode <= 299 {
		if r.Hooks.BeforePersistState != nil {
			r.Hooks.BeforePersistState(c, state)
		}

		perHostAuthStateCache.Store(origUri.Host, state)
	}

	end: return res, err
}
