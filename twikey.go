// Package twikey provides the bindings for Twikey REST APIs.
package twikey

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	baseURLV1       = "https://api.twikey.com"
	twikeyBaseAgent = "twikey-api/go-v0.1.1"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type TimeProvider interface {
	Now() time.Time
}

type DefaultTimeProvider struct{}

func (tp DefaultTimeProvider) Now() time.Time {
	return time.Now()
}

// Client is the base class, please use a dedicated UserAgent so we can notify the emergency contact
// if weird behaviour is perceived.
type Client struct {
	BaseURL      string
	APIKey       string
	PrivateKey   string
	Salt         string
	UserAgent    string
	HTTPClient   HTTPClient
	Debug        Logger
	apiToken     string
	lastLogin    time.Time
	TimeProvider TimeProvider
}

type ClientOption = func(*Client)

// WithLogger sets the Logger for the Client. If you don't want
// the Client to log anything you can pass in the NullLogger
func WithLogger(logger Logger) ClientOption {
	return func(client *Client) {
		client.Debug = logger
	}
}

// WithBaseURL will set the base URL of the API used when making requests.
//
// In production, you will probably want to use the default but if you want
// to make request to some mock API in a test environment you can use this
// to make the Client make requests to a different host.
//
// The default: https://api.twikey.com
func WithBaseURL(baseURL string) ClientOption {
	return func(client *Client) {
		client.BaseURL = baseURL
	}
}

// WithHTTPClient configures the underlying HTTP client used to make HTTP requests.
func WithHTTPClient(httpClient HTTPClient) ClientOption {
	return func(client *Client) {
		client.HTTPClient = httpClient
	}
}

// WithTimeProvider sets the TimeProvider for this Client.
func WithTimeProvider(provider TimeProvider) ClientOption {
	return func(client *Client) {
		client.TimeProvider = provider
	}
}

// WithSalt sets the salt used in generating one-time-passwords
func WithSalt(salt string) ClientOption {
	return func(client *Client) {
		client.Salt = salt
	}
}

// WithUserAgent will configure the value that is passed on in the HTTP User-Agent header
// for all requests to the Twikey API made with this Client
func WithUserAgent(userAgent string) ClientOption {
	return func(client *Client) {
		client.UserAgent = userAgent
	}
}

// NewClient is a convenience method to hit the ground running with the Twikey Rest API
func NewClient(apiKey string, opts ...ClientOption) *Client {
	c := &Client{
		BaseURL:   baseURLV1,
		APIKey:    apiKey,
		Salt:      "own",
		UserAgent: twikeyBaseAgent,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		Debug:        &NullLogger{},
		TimeProvider: DefaultTimeProvider{},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"` // translated according to Accept-Language
	Extra   string `json:"extra"`
}

// Ping Try the current credentials
func (c *Client) Ping(ctx context.Context) error {
	if err := c.refreshTokenIfRequired(ctx); err != nil {
		return err
	}
	return nil
}

func (c *Client) sendRequest(ctx context.Context, req *http.Request, v interface{}) error {

	if err := c.refreshTokenIfRequired(ctx); err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.apiToken)

	c.Debug.Tracef("Calling %s %s", req.Method, req.URL)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		c.Debug.Tracef("Error while connecting %v", err)
		return err
	}
	defer res.Body.Close()

	payload, err := io.ReadAll(res.Body)
	if err != nil {
		c.Debug.Debugf("could not read out response body from %s", req.URL.Path)
		return err
	}

	c.Debug.Tracef("Response for %s %s %s", req.Method, req.URL, string(payload))

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusBadRequest {
		if res.Header.Get("Apierror") == "err_no_login" {
			c.Debug.Tracef("Error while using apitoken, renewing")
			c.lastLogin = time.Time{} // force re-authenticate
		}
		var errRes errorResponse
		if err = json.Unmarshal(payload, &errRes); err == nil {
			return NewTwikeyError(errRes.Code, errRes.Message, errRes.Extra)
		}
		return NewTwikeyErrorFromResponse(res)
	}

	if v == nil {
		return nil
	}

	if err = json.Unmarshal(payload, v); err != nil {
		return NewTwikeyError("system_error", err.Error(), "")
	}

	return nil
}

// VerifyWebhook allows the verification of incoming webhooks.
func (c *Client) VerifyWebhook(signatureHeader string, payload string) error {
	hash := hmac.New(sha256.New, []byte(c.APIKey))
	if _, err := hash.Write([]byte(payload)); err != nil {
		c.Debug.Tracef("Error cannot compute the HMAC for request: %v", err)
		return err
	}

	expectedHash := strings.ToUpper(hex.EncodeToString(hash.Sum(nil)))
	if signatureHeader == expectedHash {
		return nil
	}
	return NewTwikeyError("invalid_params", "Invalid value", "")
}

func addIfExists(params url.Values, paramKey string, value string) {
	if value != "" {
		params.Add(paramKey, value)
	}
}
