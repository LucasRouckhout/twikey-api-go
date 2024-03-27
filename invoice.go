package twikey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type InvoiceAction int64

const (
	InvoiceAction_EMAIL    InvoiceAction = iota // Send invitation by email
	InvoiceAction_SMS                           // Send invitation by sms
	InvoiceAction_REMINDER                      // Send a reminder by email
	InvoiceAction_LETTER                        // Send the invoice via postal letter
	InvoiceAction_REOFFER                       // Reoffer (or try to collect the invoice via a recurring mechanism)
)

// Invoice is the base object for sending and receiving invoices to Twikey
type Invoice struct {
	Id     string `json:"id,omitempty"`
	Number string `json:"number"`
	// RelatedInvoice in case this is a creditNote
	RelatedInvoice     string           `json:"relatedInvoiceNumber"`
	Title              string           `json:"title"`
	Remittance         string           `json:"remittance"`
	Ct                 int              `json:"ct,omitempty"`
	Manual             bool             `json:"manual,omitempty"`
	State              string           `json:"state,omitempty"`
	Amount             float64          `json:"amount"`
	Date               string           `json:"date"`
	Duedate            string           `json:"duedate"`
	Ref                string           `json:"ref,omitempty"`
	CustomerByDocument string           `json:"customerByDocument,omitempty"`
	Customer           *Customer        `json:"customer,omitempty"`
	Pdf                []byte           `json:"pdf,omitempty"`
	Meta               *InvoiceFeedMeta `json:"meta,omitempty"`
	LastPayment        *Lastpayment     `json:"lastpayment,omitempty"`
}

type Lastpayment []map[string]interface{}

type NewInvoiceRequest struct {
	IdempotencyKey   string //   Avoid double entries
	Id               string // Allow passing the id for ubl's too
	Origin           string
	Reference        string
	Purpose          string
	Manual           bool // Don't automatically collect
	ForceTransaction bool // Ignore the state of the contract if passed
	Template         string
	Contract         string
	Invoice          *Invoice // either UBL
	UblBytes         []byte   // or an invoice item
}

// Customer is a json wrapper for usage inside the Invoice object
type Customer struct {
	CustomerNumber string `json:"customerNumber,omitempty"`
	Email          string `json:"email,omitempty"`
	CompanyName    string `json:"companyName"`
	Coc            string `json:"coc"`
	FirstName      string `json:"firstName"`
	LastName       string `json:"lastName"`
	Address        string `json:"address"`
	City           string `json:"city"`
	Zip            string `json:"zip"`
	Country        string `json:"country"`
	Language       string `json:"l"`
	Mobile         string `json:"mobile,omitempty"`
}

func (c *Customer) asUrlParams() string {
	params := url.Values{}
	addIfExists(params, "email", c.Email)
	addIfExists(params, "companyName", c.CompanyName)
	addIfExists(params, "coc", c.Coc)
	addIfExists(params, "firstname", c.FirstName)
	addIfExists(params, "lastname", c.LastName)
	addIfExists(params, "address", c.Address)
	addIfExists(params, "city", c.City)
	addIfExists(params, "zip", c.Zip)
	addIfExists(params, "country", c.Country)
	addIfExists(params, "l", c.Language)
	addIfExists(params, "mobile", c.Mobile)
	return params.Encode()
}

// InvoiceFeed is a struct to contain the response coming from Twikey, should be considered internal
type InvoiceFeed struct {
	Invoices []Invoice
}

// IsPaid convenience method
func (inv *Invoice) IsPaid() bool {
	return inv.State == "PAID"
}

// IsPending convenience method
func (inv *Invoice) IsPending() bool {
	return inv.State == "PENDING"
}

// IsFailed allows to distinguish invoices since they go from pending to booked or expired when payment failed
func (inv *Invoice) IsFailed() bool {
	return inv.State == "BOOKED" || inv.State == "EXPIRED"
}

// HasMeta convenience method to indicate that there is extra info available on the invoice
func (inv *Invoice) HasMeta() bool {
	return inv.Meta != nil
}

type InvoiceFeedMeta struct {
	LastError string `json:"lastError,omitempty"`
}

// InvoiceAdd sends an invoice to Twikey in UBL format
func (c *Client) InvoiceAdd(ctx context.Context, invoiceRequest *NewInvoiceRequest) (*Invoice, error) {

	if err := c.refreshTokenIfRequired(ctx); err != nil {
		return nil, err
	}

	var req *http.Request
	if invoiceRequest.Invoice != nil {

		// if id is passed in the request object it needs to be the same as the one in the invoice or bail out
		if invoiceRequest.Id != "" {
			if invoiceRequest.Invoice.Id == "" {
				invoiceRequest.Invoice.Id = invoiceRequest.Id
			} else if invoiceRequest.Invoice.Id != invoiceRequest.Id {
				return nil, errors.New("invoice id of request and invoice should match")
			}
		}

		invoiceBytes, err := json.Marshal(invoiceRequest)
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/creditor/invoice", bytes.NewReader(invoiceBytes))
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", c.apiToken) //Already there
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.UserAgent)
		// req.Header.Set("X-Ref", invoiceRequest.Reference)  ref already in json
		if invoiceRequest.Origin != "" {
			req.Header.Set("X-PARTNER", invoiceRequest.Origin)
		}
		if invoiceRequest.Purpose != "" {
			req.Header.Set("X-Purpose", invoiceRequest.Purpose)
		}
		if invoiceRequest.Manual {
			req.Header.Set("X-MANUAL", "true")
		}
		if invoiceRequest.ForceTransaction {
			req.Header.Set("X-FORCE-TRANSACTION", "true")
		}
		if invoiceRequest.IdempotencyKey != "" {
			req.Header.Add("Idempotency-Key", invoiceRequest.IdempotencyKey)
		}
	} else if len(invoiceRequest.UblBytes) != 0 {
		invoiceUrl := c.BaseURL + "/creditor/invoice/ubl"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, invoiceUrl, bytes.NewReader(invoiceRequest.UblBytes))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/xml")
		req.Header.Set("Authorization", c.apiToken) //Already there
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.UserAgent)
		if invoiceRequest.Id != "" {
			req.Header.Set("X-INVOICE-ID", invoiceRequest.Id)
		}
		if invoiceRequest.Template != "" {
			req.Header.Set("X-Template", invoiceRequest.Template)
		}
		if invoiceRequest.Contract != "" {
			req.Header.Set("X-CONTRACT", invoiceRequest.Contract)
		}
		if invoiceRequest.Origin != "" {
			req.Header.Set("X-Partner", invoiceRequest.Origin)
		}
		if invoiceRequest.Purpose != "" {
			req.Header.Set("X-Purpose", invoiceRequest.Purpose)
		}
		if invoiceRequest.Manual {
			req.Header.Set("X-Manual", "true")
		}
		if invoiceRequest.ForceTransaction {
			req.Header.Set("X-FORCE-TRANSACTION", "true")
		}
		if invoiceRequest.Reference != "" {
			req.Header.Set("X-Ref", invoiceRequest.Reference)
		}
		if invoiceRequest.IdempotencyKey != "" {
			req.Header.Add("Idempotency-Key", invoiceRequest.IdempotencyKey)
		}
	} else {
		return nil, &TwikeyError{
			Status:  0,
			Code:    "invalid_request",
			Message: "Either ubl or invoice struct is required",
		}
	}

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode == 200 {
		payload, _ := io.ReadAll(res.Body)
		c.Debug.Debugf("TwikeyInvoice: %s", string(payload))
		if res.Header["X-Warning"] != nil {
			c.Debug.Debugf("Warning for new invoice with ref=%s : %s", invoiceRequest.Reference, res.Header["X-Warning"])
		}
		var invoice Invoice
		err := json.Unmarshal(payload, &invoice)
		if err != nil {
			return nil, err
		}
		return &invoice, nil
	}

	errLoad, _ := io.ReadAll(res.Body)
	c.Debug.Debugf("Error sending invoice to Twikey: %s", string(errLoad))
	return nil, NewTwikeyErrorFromResponse(res)
}

// InvoiceFeed Get invoice Feed twikey
func (c *Client) InvoiceFeed(ctx context.Context, callback func(invoice *Invoice), sideloads ...string) error {

	if err := c.refreshTokenIfRequired(ctx); err != nil {
		return err
	}

	_url := c.BaseURL + "/creditor/invoice"
	for i, sideload := range sideloads {
		if i == 0 {
			_url = _url + "?include=" + sideload
		} else {
			_url = _url + "&include=" + sideload
		}
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, _url, nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", c.apiToken) //Already there
	req.Header.Set("User-Agent", c.UserAgent)

	var feeds InvoiceFeed
	var moreInvoices = true

	for moreInvoices {
		if err := c.sendRequest(ctx, req, &feeds); err != nil {
			return err
		}

		for _, invoice := range feeds.Invoices {
			callback(&invoice)
		}

		moreInvoices = len(feeds.Invoices) >= 100
	}
	return nil
}

// InvoiceDetail allows a snapshot of a particular invoice, note that this is rate limited
func (c *Client) InvoiceDetail(ctx context.Context, invoiceIdOrNumber string, sideloads ...string) (*Invoice, error) {

	if err := c.refreshTokenIfRequired(ctx); err != nil {
		return nil, err
	}

	_url := c.BaseURL + "/creditor/invoice/" + invoiceIdOrNumber
	for i, sideload := range sideloads {
		if i == 0 {
			_url = _url + "?include=" + sideload
		} else {
			_url = _url + "&include=" + sideload
		}
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, _url, nil)
	req.Header.Add("Accept-Language", "en")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Add("Authorization", c.apiToken)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode == 200 {
		payload, _ := io.ReadAll(res.Body)

		var invoice Invoice
		err := json.Unmarshal(payload, &invoice)
		if err != nil {
			return nil, err
		}

		return &invoice, nil
	}
	return nil, NewTwikeyErrorFromResponse(res)
}

// InvoiceAction allows certain actions to be done on an existing invoice
func (c *Client) InvoiceAction(ctx context.Context, invoiceIdOrNumber string, action InvoiceAction) error {

	if err := c.refreshTokenIfRequired(ctx); err != nil {
		return err
	}

	_url := c.BaseURL + "/creditor/invoice/" + invoiceIdOrNumber + "/action"
	params := url.Values{}

	switch action {
	case InvoiceAction_EMAIL:
		params.Add("type", "email")
	case InvoiceAction_SMS:
		params.Add("type", "sms")
	case InvoiceAction_LETTER:
		params.Add("type", "letter")
	case InvoiceAction_REMINDER:
		params.Add("type", "reminder")
	case InvoiceAction_REOFFER:
		params.Add("type", "reoffer")
	default:
		return errors.New("invalid action")
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, _url, strings.NewReader(params.Encode()))
	req.Header.Add("Accept-Language", "en")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Add("Authorization", c.apiToken)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == 204 {
		return nil
	}
	return NewTwikeyErrorFromResponse(res)
}

// InvoicePayment allows marking an existing invoice as paid
func (c *Client) InvoicePayment(ctx context.Context, invoiceIdOrNumber string, method string, paymentdate string) error {

	if err := c.refreshTokenIfRequired(ctx); err != nil {
		return err
	}

	_url := c.BaseURL + "/creditor/invoice/" + invoiceIdOrNumber + "/action"
	params := url.Values{}
	params.Add("type", "manualPayment")
	params.Add("rsn", method)
	params.Add("date", paymentdate)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, _url, strings.NewReader(params.Encode()))
	req.Header.Add("Accept-Language", "en")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Add("Authorization", c.apiToken)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == 204 {
		return nil
	}
	return NewTwikeyErrorFromResponse(res)
}
