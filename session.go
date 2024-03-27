package twikey

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func generateOtp(_salt string, _privKey string) (int, error) {

	salt := []byte(_salt)
	privkey, err := hex.DecodeString(_privKey)

	if err != nil {
		return 0, err
	}

	total := len(salt) + len(privkey)
	key := make([]byte, total)
	copy(key, salt)
	copy(key[len(salt):], privkey)

	buf := make([]byte, 8)
	_time := time.Now().UTC().Unix() //*1000
	counter := uint64(_time / 30)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha256.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	offset := hash[19] & 0xf
	v := int64(((int(hash[offset]) & 0x7f) << 24) |
		((int(hash[offset+1] & 0xff)) << 16) |
		((int(hash[offset+2] & 0xff)) << 8) |
		(int(hash[offset+3]) & 0xff))

	// last 8 digits are important
	return int(v % 100000000), nil
}

func (c *Client) refreshTokenIfRequired(ctx context.Context) error {

	if c.TimeProvider.Now().Sub(c.lastLogin).Hours() < 23 {
		return nil
	}

	params := url.Values{}
	params.Add("apiToken", c.APIKey)
	if c.PrivateKey != "" {
		otp, _ := generateOtp(c.Salt, c.PrivateKey)
		params.Add("otp", fmt.Sprint(otp))
	}

	c.Debug.Tracef("Connecting to %s with %s", c.BaseURL, c.APIKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/creditor", strings.NewReader(params.Encode()))
	if err != nil {
		c.Debug.Debugf("Error while connecting : %v", err)
		return err
	}

	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		c.apiToken = ""
		c.lastLogin = time.Unix(0, 0)
		return err
	}
	defer resp.Body.Close()

	token := resp.Header["Authorization"]
	errcode := resp.Header["Apierror"]

	if resp.StatusCode != http.StatusOK || token == nil {
		switch {
		case resp.StatusCode > http.StatusInternalServerError:
			{
				c.Debug.Tracef("General error : [%d] %s", resp.StatusCode, resp.Status)
				return NewTwikeyErrorFromResponse(resp)
			}
		case resp.StatusCode > http.StatusOK:
			{
				c.Debug.Tracef("Other error : [%d] %s", resp.StatusCode, resp.Status)
				return NewTwikeyErrorFromResponse(resp)
			}
		case errcode != nil:
			{
				c.Debug.Tracef("Error invalid apiToken status = %s", errcode[0])
				return NewTwikeyError(errcode[0], "Invalid apiToken", "")
			}
		}
	}

	c.Debug.Tracef("Connected to %s with token %s", c.BaseURL, token[0])
	c.apiToken = token[0]
	c.lastLogin = c.TimeProvider.Now()
	return nil
}
