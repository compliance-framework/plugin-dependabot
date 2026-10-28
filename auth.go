package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"golang.org/x/oauth2"
)

// AuthConfig is how the plugin authenticates to GitHub: a token (personal access token or
// any other bearer token) or a GitHub App installation. A token wins when both are set.
type AuthConfig struct {
	Token string `mapstructure:"token"`

	// GitHub App authentication. The plugin exchanges the app's private key for short-lived
	// installation tokens, renewed as they expire.
	AppID          string `mapstructure:"app-id"`
	InstallationID string `mapstructure:"installation-id"`
	// The PEM private key, from a file (preferred: keeps the key out of the config) or inline,
	// base64-encoded or as plain PEM.
	PrivateKeyFile string `mapstructure:"private-key-file"`
	PrivateKey     string `mapstructure:"private-key"`
}

// validateAuth rejects incomplete GitHub App credentials. With neither a token nor app
// credentials the plugin calls GitHub unauthenticated, as it always has.
func (c *AuthConfig) validateAuth() error {
	if c.Token != "" || !c.hasAppCredentials() {
		return nil
	}
	var missing []string
	if c.AppID == "" {
		missing = append(missing, "app-id")
	}
	if c.InstallationID == "" {
		missing = append(missing, "installation-id")
	}
	if c.PrivateKeyFile == "" && c.PrivateKey == "" {
		missing = append(missing, "private-key-file or private-key")
	}
	if len(missing) > 0 {
		return fmt.Errorf("GitHub App authentication needs %s", strings.Join(missing, ", "))
	}
	if c.PrivateKeyFile != "" && c.PrivateKey != "" {
		return errors.New("only one of private-key-file or private-key may be set")
	}
	return nil
}

func (c *AuthConfig) hasAppCredentials() bool {
	return c.AppID != "" || c.InstallationID != "" || c.PrivateKeyFile != "" || c.PrivateKey != ""
}

// httpClient returns an HTTP client that authenticates every request to GitHub, or nil (the
// default, unauthenticated client) when no credentials are configured.
func (c *AuthConfig) httpClient(ctx context.Context) (*http.Client, error) {
	if c.Token != "" {
		return oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: c.Token})), nil
	}
	if !c.hasAppCredentials() {
		return nil, nil
	}

	appID, err := strconv.ParseInt(c.AppID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing app-id: %w", err)
	}
	installationID, err := strconv.ParseInt(c.InstallationID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing installation-id: %w", err)
	}
	key, err := c.privateKey()
	if err != nil {
		return nil, err
	}
	transport, err := ghinstallation.New(http.DefaultTransport, appID, installationID, key)
	if err != nil {
		return nil, fmt.Errorf("creating GitHub App installation transport: %w", err)
	}
	return &http.Client{Transport: transport}, nil
}

func (c *AuthConfig) privateKey() ([]byte, error) {
	if c.PrivateKeyFile != "" {
		key, err := os.ReadFile(c.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("reading private-key-file: %w", err)
		}
		return key, nil
	}
	key := strings.TrimSpace(c.PrivateKey)
	if strings.HasPrefix(key, "-----BEGIN") {
		return []byte(key), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("decoding private-key (expected PEM or base64-encoded PEM): %w", err)
	}
	return decoded, nil
}
