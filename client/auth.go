/*
 * Pacrat
 * Copyright (C) 2024 Ariel Abreu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

const KEYRING_SERVICE_NAME string = "pacrat-cli"

type AuthInfo struct {
	OidcEndpoint string `json:"oidc_endpoint"`
	ClientID     string `json:"client_id"`
}

type CheckTokenResponse struct {
	Message     string `json:"message"`
	AccessLevel string `json:"access_level"`
}

type KeyringEntry struct {
	Issuer   string       `json:"issuer"`
	ClientID string       `json:"client_id"`
	Token    oauth2.Token `json:"token"`
}

type ClientInfo struct {
	Server string
	AuthInfo
}

func oauthRedirectServer(server *http.Server, listener net.Listener, authCode chan<- string) {
	onceCode := &sync.Once{}
	http.HandleFunc("/", func(writer http.ResponseWriter, req *http.Request) {
		code := req.URL.Query().Get("code")
		if code == "" {
			writer.WriteHeader(http.StatusUnprocessableEntity)
			writer.Write([]byte("422 Unprocessable entity (missing `code`)"))
			return
		}
		cookie, _ := req.Cookie("nonce")
		// we can safely ignore the error: the only error is returns is ErrNoCookie,
		// but we don't care if the cookie isn't present
		done := false
		onceCode.Do(func() {
			authCode <- code
			if cookie == nil {
				authCode <- ""
			} else {
				authCode <- cookie.Value
			}
			close(authCode)
			done = true
		})
		if done {
			writer.Write([]byte("200 OK"))
		} else {
			writer.WriteHeader(http.StatusGone)
			writer.Write([]byte("410 Gone"))
		}
	})
	server.Serve(listener)
}

func fetchServerAuthInfo(server string) (AuthInfo, error) {
	authInfo := AuthInfo{}

	resp, err := http.Get(server + "/auth_info")
	if err != nil {
		return authInfo, fmt.Errorf("failed to get authentication info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return authInfo, fmt.Errorf("failed to read authentication info body: %w", err)
	}

	if json.Unmarshal(body, &authInfo) != nil {
		return authInfo, fmt.Errorf("failed to unmarshal response JSON: %w", err)
	}

	if authInfo.OidcEndpoint == "" {
		return authInfo, fmt.Errorf("invalid OIDC endpoint (empty string)")
	}

	if authInfo.ClientID == "" {
		return authInfo, fmt.Errorf("invalid client ID (empty string)")
	}

	return authInfo, nil
}

func getAccessTokenInteractively(oauthConfig oauth2.Config, oidcVerifier *oidc.IDTokenVerifier) (*oauth2.Token, *oidc.IDToken, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup redirect listener")
	}

	redirectPort := listener.Addr().(*net.TCPAddr).Port
	redirectServer := &http.Server{}

	authCodeChannel := make(chan string)

	go oauthRedirectServer(redirectServer, listener, authCodeChannel)
	defer redirectServer.Shutdown(context.Background())

	oauthConfig.RedirectURL = "http://127.0.0.1:" + strconv.Itoa(redirectPort)

	verifier := oauth2.GenerateVerifier()
	authCodeURL := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))
	fmt.Println("Please visit the following URL to login:", authCodeURL)

	authCode := <-authCodeChannel
	nonce := <-authCodeChannel

	redirectServer.Shutdown(context.Background())

	authToken, err := oauthConfig.Exchange(context.Background(), authCode, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve access token: %w", err)
	}

	rawIDToken, ok := authToken.Extra("id_token").(string)
	if !ok {
		return nil, nil, fmt.Errorf("invalid ID token in response (not a string)")
	}

	idToken, err := oidcVerifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid ID token in response (failed to verify): %w", err)
	}

	if nonce != "" && idToken.Nonce != nonce {
		return nil, nil, fmt.Errorf("invalid ID token in response (incorrect nonce)")
	}

	return authToken, idToken, nil
}

func getServerClient(server string) (*http.Client, ClientInfo, error) {
	clientInfo := ClientInfo{
		Server: server,
	}

	authInfo, err := fetchServerAuthInfo(server)
	if err != nil {
		return nil, clientInfo, err
	}

	clientInfo.AuthInfo = authInfo

	provider, err := oidc.NewProvider(context.Background(), authInfo.OidcEndpoint)
	if err != nil {
		return nil, clientInfo, fmt.Errorf("failed to load OIDC provider information: %w", err)
	}

	oidcConfig := &oidc.Config{
		ClientID: authInfo.ClientID,
	}

	oidcVerifier := provider.Verifier(oidcConfig)

	oauthConfig := oauth2.Config{
		ClientID: authInfo.ClientID,

		Endpoint: provider.Endpoint(),

		Scopes: []string{oidc.ScopeOpenID, "profile", "email", "pacrat_access", "offline_access"},
	}

	var authToken *oauth2.Token = nil

	rawKeyringEntry, err := keyring.Get(KEYRING_SERVICE_NAME, server)
	if err == nil {
		// try to use the stored token
		keyringEntry := KeyringEntry{}
		json.Unmarshal([]byte(rawKeyringEntry), &keyringEntry)
		if keyringEntry.Issuer != authInfo.OidcEndpoint || keyringEntry.ClientID != authInfo.ClientID || keyringEntry.Token.AccessToken == "" || keyringEntry.Token.RefreshToken == "" {
			// invalid keyring entry; let's remove it and acquire a new token
			err = fmt.Errorf("invalid keyring entry")
			// ignore the error; we don't care if it doesn't exist anymore (that's what we want anyways)
			_ = keyring.Delete(KEYRING_SERVICE_NAME, server)
		} else {
			// construct an auth token based on the keyring entry data
			//
			// this token may be expired, in which case the oauth2.Client we use below
			// will automatically try to refresh it. however, it may be the case that even the
			// refresh token has expired; we'll handle that below as well.
			authToken = &oauth2.Token{}
			*authToken = keyringEntry.Token
		}
	}
	if err != nil {
		// get a new auth token
		authToken, _, err = getAccessTokenInteractively(oauthConfig, oidcVerifier)
		if err != nil {
			return nil, clientInfo, fmt.Errorf("failed to retrieve access token: %w", err)
		}
	}

	client := oauthConfig.Client(context.Background(), authToken)

	resp, err := client.Get(server + "/check_token")
	if urlErr, ok := err.(*url.Error); ok {
		if _, ok := urlErr.Unwrap().(*oauth2.RetrieveError); ok {
			// we might have been using a stale access token with a stale refresh token; let's try to get a new access token
			authToken, _, err = getAccessTokenInteractively(oauthConfig, oidcVerifier)
			if err != nil {
				return nil, clientInfo, fmt.Errorf("failed to retrieve access token: %w", err)
			}

			client = oauthConfig.Client(context.Background(), authToken)
			resp, err = client.Get(server + "/check_token")
		}
	}
	if err != nil {
		return nil, clientInfo, fmt.Errorf("failed to check token with server: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, clientInfo, fmt.Errorf("failed to read token check body: %w", err)
	}

	checkTokenResponse := CheckTokenResponse{}
	if json.Unmarshal(body, &checkTokenResponse) != nil {
		return nil, clientInfo, fmt.Errorf("failed to unmarshal response JSON: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, clientInfo, fmt.Errorf("token failed check: %s", checkTokenResponse.Message)
	}

	return client, clientInfo, nil
}

// store the client token for future use
func saveClientToken(client *http.Client, clientInfo ClientInfo) error {
	authToken, err := client.Transport.(*oauth2.Transport).Source.Token()
	if err != nil {
		return err
	}

	keyringEntry := KeyringEntry{
		Issuer:   clientInfo.OidcEndpoint,
		ClientID: clientInfo.ClientID,
		Token:    *authToken,
	}

	keyringEntryData, err := json.Marshal(&keyringEntry)
	if err != nil {
		return err
	}

	return keyring.Set(KEYRING_SERVICE_NAME, clientInfo.Server, string(keyringEntryData))
}
