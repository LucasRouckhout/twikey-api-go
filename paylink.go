package twikey

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// PaylinkRequest is the base object for sending and receiving paylinks to Twikey
type PaylinkRequest struct {
	CustomerNumber string  //	The customer number (strongly advised)
	IdempotencyKey string  //   Avoid double entries
	Email          string  //	Email of the debtor	(Required to send invite)
	Lastname       string  //	lastname
	Firstname      string  //	firstname
	Language       string  //	Language (en/fr/nl/de/pt/es/it)
	Mobile         string  //	mobile number
	Template       string  //	contract template
	Title          string  //	Message to the debto
	Remittance     string  //	Payment message, if empty then title will be used
	Amount         float64 //	Amount to be billed
	RedirectUrl    string  //	Optional redirect after pay url (must use http(s)://)
	Place          string  //	Optional place
	Expiry         string  //	Optional expiration date
	SendInvite     string  //	Send out invite email or sms directly (email, sms)
	Address        string  //	Address (street + number)
	City           string  //	City of debtor
	Zip            string  //	Zipcode of debtor
	Country        string  //	ISO format (2 letters)
	Txref          string  //	References from existing transactions
	Method         string  //	Circumvents the payment selection with PSP (bancontact/ideal/maestro/mastercard/visa/inghomepay/kbc/belfius)
	Invoice        string  //	create payment link for specific invoice number
	Extra          map[string]string
}

func (request *PaylinkRequest) Add(key string, value string) {
	request.Extra[key] = value
}

// Paylink is the response receiving from Twikey upon a request
type Paylink struct {
	Id     int64   `json:"id,omitempty"`
	Amount float64 `json:"amount,omitempty"`
	Msg    string  `json:"msg,omitempty"`
	Ref    string  `json:"ref,omitempty"`
	State  string  `json:"state,omitempty"`
	Url    string  `json:"url,omitempty"`
}

type PaylinkList struct {
	Links []Paylink
}

// PaylinkNew sends the new paylink to Twikey for creation
func (c *Client) PaylinkNew(ctx context.Context, paylinkRequest *PaylinkRequest) (*Paylink, error) {

	params := url.Values{}
	addIfExists(params, "ct", paylinkRequest.Template)
	addIfExists(params, "title", paylinkRequest.Title)
	addIfExists(params, "remittance", paylinkRequest.Remittance)
	addIfExists(params, "amount", fmt.Sprintf("%.2f", paylinkRequest.Amount))
	addIfExists(params, "redirectUrl", paylinkRequest.RedirectUrl)
	addIfExists(params, "place", paylinkRequest.Place)
	addIfExists(params, "expiry", paylinkRequest.Expiry)
	addIfExists(params, "sendInvite", paylinkRequest.SendInvite)
	addIfExists(params, "txref", paylinkRequest.Txref)
	addIfExists(params, "method", paylinkRequest.Method)
	addIfExists(params, "invoice", paylinkRequest.Invoice)

	addIfExists(params, "customerNumber", paylinkRequest.CustomerNumber)
	addIfExists(params, "email", paylinkRequest.Email)
	addIfExists(params, "lastname", paylinkRequest.Lastname)
	addIfExists(params, "firstname", paylinkRequest.Firstname)
	addIfExists(params, "l", paylinkRequest.Language)
	addIfExists(params, "mobile", paylinkRequest.Mobile)
	addIfExists(params, "address", paylinkRequest.Address)
	addIfExists(params, "city", paylinkRequest.City)
	addIfExists(params, "zip", paylinkRequest.Zip)
	addIfExists(params, "country", paylinkRequest.Country)
	if paylinkRequest.Extra != nil {
		for k, v := range paylinkRequest.Extra {
			addIfExists(params, k, v)
		}
	}

	c.Debug.Debugf("New link : %s", params.Encode())

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/creditor/payment/link", strings.NewReader(params.Encode()))
	if paylinkRequest.IdempotencyKey != "" {
		req.Header.Add("Idempotency-Key", paylinkRequest.IdempotencyKey)
	}

	var paylink Paylink
	err := c.sendRequest(ctx, req, &paylink)
	if err != nil {
		return nil, err
	}
	return &paylink, nil
}

// PaylinkFeed retrieves the feed of updated paylinks since last call
func (c *Client) PaylinkFeed(ctx context.Context, callback func(paylink *Paylink), sideloads ...string) error {

	if err := c.refreshTokenIfRequired(ctx); err != nil {
		return err
	}

	_url := c.BaseURL + "/creditor/payment/link/feed"
	for i, sideload := range sideloads {
		if i == 0 {
			_url = _url + "?include=" + sideload
		} else {
			_url = _url + "&include=" + sideload
		}
	}

	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, _url, nil)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("Authorization", c.apiToken)
		req.Header.Set("User-Agent", c.UserAgent)

		res, err := c.HTTPClient.Do(req)
		if err != nil {
			return err
		}
		if res.StatusCode == 200 {
			payload, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			var paylinks PaylinkList
			err := json.Unmarshal(payload, &paylinks)
			if err == nil {
				c.Debug.Debugf("Fetched %d links", len(paylinks.Links))
				for _, paylink := range paylinks.Links {
					callback(&paylink)
				}
			} else {
				return err
			}
			if len(paylinks.Links) == 0 {
				return nil
			}
		} else {
			c.Debug.Debugf("Error response from Twikey: %d", res.StatusCode)
			return NewTwikeyErrorFromResponse(res)
		}
	}
}
