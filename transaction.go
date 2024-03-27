package twikey

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TransactionRequest is the payload to be send to Twikey when a new transaction should be send
type TransactionRequest struct {
	IdempotencyKey                string
	DocumentReference             string
	TransactionDate               string
	RequestedCollection           string
	Msg                           string
	Ref                           string
	Amount                        float64
	Place                         string
	ReferenceIsEndToEndIdentifier bool
	Reservation                   string // via reservation request
	Force                         bool
}

// ReservationRequest is the payload to be send to Twikey when a new transaction should be send
type ReservationRequest struct {
	IdempotencyKey    string
	DocumentReference string
	Amount            float64
	Minimum           float64
	Expiration        *time.Time
	Force             bool
}

// Transaction is the response from Twikey when updates are received
type Transaction struct {
	Id                  int64   `json:"id,omitempty"`
	DocumentId          int64   `json:"contractId,omitempty"`
	DocumentReference   string  `json:"mndtId"`
	Amount              float64 `json:"amount"`
	Message             string  `json:"msg"`
	Ref                 string  `json:"ref"`
	Place               string  `json:"place"`
	Final               bool    `json:"final"`
	State               string  `json:"state"`
	BookedDate          string  `json:"bkdate"`
	BookedError         string  `json:"bkerror"`
	BookedAmount        float64 `json:"bkamount"`
	RequestedCollection string  `json:"reqcolldt"`
}

// Reservation is the response from Twikey when updates are received
type Reservation struct {
	Id             string    `json:"id"`
	MndtId         string    `json:"mndtId"`
	ReservedAmount float64   `json:"reservedAmount"`
	Expires        time.Time `json:"expires"`
}

// TransactionList is a struct to contain the response coming from Twikey, should be considered internal
type TransactionList struct {
	Entries []Transaction
}

// CollectResponse is a struct to contain the response coming from Twikey, should be considered internal
type CollectResponse struct {
	ID string `json:"rcurMsgId"`
}

// TransactionNew sends a new transaction to Twikey
func (c *Client) TransactionNew(ctx context.Context, transaction *TransactionRequest) (*Transaction, error) {

	params := url.Values{}
	params.Add("mndtId", transaction.DocumentReference)
	params.Add("date", transaction.TransactionDate)
	params.Add("reqcolldt", transaction.RequestedCollection)
	params.Add("amount", fmt.Sprintf("%.2f", transaction.Amount))
	params.Add("message", transaction.Msg)
	params.Add("ref", transaction.Ref)
	params.Add("place", transaction.Place)
	if transaction.Force {
		params.Add("force", "true")
	}
	if transaction.ReferenceIsEndToEndIdentifier {
		params.Add("refase2e", "true")
	}

	c.Debug.Debugf("New transaction %s", params)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/creditor/transaction", strings.NewReader(params.Encode()))
	if transaction.IdempotencyKey != "" {
		req.Header.Add("Idempotency-Key", transaction.IdempotencyKey)
	}
	if transaction.Reservation != "" {
		req.Header.Add("X-RESERVATION", transaction.Reservation)
	}
	var transactionList TransactionList
	err := c.sendRequest(ctx, req, &transactionList)
	if err != nil {
		return nil, err
	}
	return &transactionList.Entries[0], nil
}

// ReservationNew sends a new reservation to Twikey
func (c *Client) ReservationNew(ctx context.Context, reservationRequest *ReservationRequest) (*Reservation, error) {

	params := url.Values{}
	params.Add("mndtId", reservationRequest.DocumentReference)
	params.Add("message", "ignore")
	params.Add("amount", fmt.Sprintf("%.2f", reservationRequest.Amount))
	if reservationRequest.Minimum != 0 {
		params.Add("reservationMinimum", fmt.Sprintf("%.2f", reservationRequest.Minimum))
	}
	if reservationRequest.Expiration != nil {
		params.Add("reservationExpiration", reservationRequest.Expiration.UTC().Format(time.RFC3339))
	}
	params.Add("reservation", "true")
	if reservationRequest.Force {
		params.Add("force", "true")
	}

	c.Debug.Debugf("New reservation %s", params)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/creditor/reservation", strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	if reservationRequest.IdempotencyKey != "" {
		req.Header.Add("Idempotency-Key", reservationRequest.IdempotencyKey)
	}

	reservation := &Reservation{}
	if err := c.sendRequest(ctx, req, reservation); err != nil {
		return nil, err
	}

	return reservation, nil
}

// TransactionFeed retrieves all transaction updates since the last call with a callback since there may be many
func (c *Client) TransactionFeed(ctx context.Context, callback func(transaction *Transaction), sideloads ...string) error {

	if err := c.refreshTokenIfRequired(ctx); err != nil {
		return err
	}

	_url := c.BaseURL + "/creditor/transaction"
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
			var paymentResponse TransactionList
			err := json.Unmarshal(payload, &paymentResponse)
			if err == nil {
				c.Debug.Debugf("Fetched %d transactions", len(paymentResponse.Entries))
				for _, transaction := range paymentResponse.Entries {
					callback(&transaction)
				}
			} else {
				return err
			}
			if len(paymentResponse.Entries) == 0 {
				return nil
			}
		} else {
			c.Debug.Debugf("Error response from Twikey: %d", res.StatusCode)
			return NewTwikeyErrorFromResponse(res)
		}
	}
}

type CollectOptions struct {
	// Until is used to filter the eventual transactions that will be sent for collection
	// this value is interpreted as a unix timestamp using milliseconds precision. Any
	// transaction that was logged before this timestamp will be ignored.
	// The default value is 0 and will result in this parameter not being used.
	Until int64
}

type CollectionOptionFunc = func(options CollectOptions)

// WithUntil will set the value for the "until" parameter.
// It is used to filter the eventual transactions that will be sent for collection
// this value is interpreted as a unix timestamp using milliseconds precision. Any
// transaction that was logged before this timestamp will be ignored.
// The default value is 0 and will result in this parameter not being used.
func WithUntil(until int64) CollectionOptionFunc {
	return func(options CollectOptions) {
		options.Until = until
	}
}

// TransactionCollect collects all open transaction
func (c *Client) TransactionCollect(ctx context.Context, template string, prenotify bool, opts ...CollectionOptionFunc) (string, error) {
	opt := CollectOptions{}

	for _, f := range opts {
		f(opt)
	}

	if err := c.refreshTokenIfRequired(ctx); err != nil {
		return "", err
	}

	if template == "" {
		return "", NewTwikeyError("err_invalid_template", "A template is required", "")
	}

	params := url.Values{}
	if _, err := strconv.Atoi(template); err == nil {
		params.Add("ct", template)
	} else {
		params.Add("tc", template)
	}
	// TODO: Add this the the optional parameters
	if prenotify {
		params.Add("prenotify", "true")
	}

	if opt.Until != 0 {
		params.Add("until", strconv.FormatInt(opt.Until, 10))
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/creditor/collect", strings.NewReader(params.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", c.apiToken)
	req.Header.Set("User-Agent", c.UserAgent)
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	if res.StatusCode == 200 {
		payload, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		var collectionResponse CollectResponse
		err := json.Unmarshal(payload, &collectionResponse)
		if err == nil && collectionResponse.ID != "" {
			c.Debug.Debugf("Collected transaction for %s into %s", template, collectionResponse.ID)
			return collectionResponse.ID, nil
		} else {
			return "", err
		}
	} else {
		c.Debug.Debugf("Error response from Twikey: %d", res.StatusCode)
		return "", NewTwikeyErrorFromResponse(res)
	}
}
