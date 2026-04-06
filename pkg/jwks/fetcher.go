package jwks

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// GetPublicKey converts the raw string N and E to a standard crypto.PublicKey
func (k *JWK) GetPublicKey() (crypto.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", k.Kty)
	}

	decodeBase64URL := func(s string) ([]byte, error) {
		return base64.RawURLEncoding.DecodeString(s)
	}

	decN, err := decodeBase64URL(k.N)
	if err != nil {
		return nil, fmt.Errorf("invalid modulus (N): %w", err)
	}
	n := new(big.Int).SetBytes(decN)

	decE, err := decodeBase64URL(k.E)
	if err != nil {
		return nil, fmt.Errorf("invalid exponent (E): %w", err)
	}
	
	var eInt int
	for _, b := range decE {
		eInt = (eInt << 8) | int(b)
	}

	return &rsa.PublicKey{N: n, E: eInt}, nil
}

type cachedKeys struct {
	Keys      map[string]crypto.PublicKey // kid -> PublicKey
	expiresAt time.Time
}

type ExternalJWKSFetcher struct {
	cache      map[string]*cachedKeys // issuer -> cached keys
	discovery  map[string]string      // issuer -> jwks_uri
	mu         sync.RWMutex
	httpClient *http.Client
}

func NewExternalJWKSFetcher() *ExternalJWKSFetcher {
	return &ExternalJWKSFetcher{
		cache:      make(map[string]*cachedKeys),
		discovery:  make(map[string]string),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// GetPublicKey fetches the public key from the issuer's JWKS endpoint based on kid.
func (f *ExternalJWKSFetcher) GetPublicKey(issuer, kid string) (crypto.PublicKey, error) {
	// First, try to get JWKS from cache
	f.mu.RLock()
	c, jwksFound := f.cache[issuer]
	f.mu.RUnlock()

	var keys map[string]crypto.PublicKey
	var err error

	// If not found or expired, fetch it
	if !jwksFound || time.Now().After(c.expiresAt) {
		keys, err = f.fetchAndCacheJWKS(issuer)
		if err != nil {
			return nil, err
		}
	} else {
		keys = c.Keys
	}

	// Find the key by kid
	if rawKey, ok := keys[kid]; ok {
		return rawKey, nil
	}

	// If kid not found, it might be a new key rotated recently. Force fetch one more time.
	keys, err = f.fetchAndCacheJWKS(issuer)
	if err != nil {
		return nil, err
	}

	rawKey, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("key %s not found in issuer %s's JWKS", kid, issuer)
	}

	return rawKey, nil
}

func (f *ExternalJWKSFetcher) fetchAndCacheJWKS(issuer string) (map[string]crypto.PublicKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Double check cache in case another goroutine fetched it while we waited for lock
	if c, ok := f.cache[issuer]; ok && time.Now().Before(c.expiresAt) {
		return c.Keys, nil
	}

	// 1. Get JWKS URI from discovery if not available
	jwksURI, ok := f.discovery[issuer]
	if !ok {
		discoveryURL := issuer + "/.well-known/openid-configuration"
		resp, err := f.httpClient.Get(discoveryURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch discovery document: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
		}

		var disc map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
			return nil, fmt.Errorf("failed to parse discovery document: %v", err)
		}

		uri, ok := disc["jwks_uri"].(string)
		if !ok || uri == "" {
			return nil, errors.New("jwks_uri not found in discovery document")
		}
		jwksURI = uri
		f.discovery[issuer] = jwksURI
	}

	// 2. Fetch JWKS
	resp, err := f.httpClient.Get(jwksURI)
	if err != nil {
		delete(f.discovery, issuer) // clear in case URI changed
		return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		delete(f.discovery, issuer)
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %v", err)
	}

	// 3. Parse keys into crypto.PublicKey map
	parsedKeys := make(map[string]crypto.PublicKey)
	for _, k := range jwks.Keys {
		if k.Use != "sig" || k.Kty != "RSA" {
			continue // skip encryption keys or non-RSA
		}
		pubKey, err := k.GetPublicKey()
		if err == nil {
			parsedKeys[k.Kid] = pubKey
		}
	}

	// Cache for 1 hour
	f.cache[issuer] = &cachedKeys{
		Keys:      parsedKeys,
		expiresAt: time.Now().Add(1 * time.Hour),
	}

	return parsedKeys, nil
}
