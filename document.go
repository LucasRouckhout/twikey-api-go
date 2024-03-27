package twikey

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// InviteRequest contains all possible parameters that can be send to invite a customer
// to sign a document
type InviteRequest struct {
	Template       string // mandatory
	CustomerNumber string
	Email          string
	Mobile         string
	Language       string
	Lastname       string
	Firstname      string
	MandateNumber  string
	ContractNumber string
	CompanyName    string
	Coc            string
	Address        string
	City           string
	Zip            string
	Country        string
	SignDate       string
	Amount         string
	Iban           string
	Bic            string
	Campaign       string
	Method         string
	Extra          map[string]string
}

func (request *InviteRequest) asUrlParams() string {
	params := url.Values{}
	addIfExists(params, "ct", request.Template)
	addIfExists(params, "customerNumber", request.CustomerNumber)
	addIfExists(params, "email", request.Email)
	addIfExists(params, "mobile", request.Mobile)
	addIfExists(params, "l", request.Language)
	addIfExists(params, "lastname", request.Lastname)
	addIfExists(params, "firstname", request.Firstname)
	addIfExists(params, "mandateNumber", request.MandateNumber)
	addIfExists(params, "contractNumber", request.ContractNumber)
	addIfExists(params, "companyName", request.CompanyName)
	addIfExists(params, "coc", request.Coc)

	addIfExists(params, "address", request.Address)
	addIfExists(params, "city", request.City)
	addIfExists(params, "zip", request.Zip)
	addIfExists(params, "country", request.Country)

	addIfExists(params, "overrideFromDate", request.SignDate)
	addIfExists(params, "amount", request.Amount)
	addIfExists(params, "iban", request.Iban)
	addIfExists(params, "bic", request.Bic)
	addIfExists(params, "campaign", request.Campaign)
	addIfExists(params, "method", request.Method)

	if request.Extra != nil {
		for k, v := range request.Extra {
			addIfExists(params, k, v)
		}
	}
	return params.Encode()
}

func (request *InviteRequest) Add(key string, value string) {
	request.Extra[key] = value
}

// Invite is the response containing the documentNumber, key and the url to point the customer too.
type Invite struct {
	MndtId string // documentNumber
	Url    string // where the customer can sign the document
	Key    string // specific invite key
}

// UpdateRequest contains all possible parameters that can be send to update a document
type UpdateRequest struct {
	MandateNumber  string // Document or MandateNumber
	ContractNumber string // ContractNumber
	State          string // active or passive (activated or suspend mandate)
	Mobile         string // Owner's mobile number
	Iban           string // Debtor's IBAN
	Bic            string // Debtor's BIC code
	Email          string // email address of debtor
	Firstname      string // Firstname of the debtor
	Lastname       string // Lastname of the debtor
	CompanyName    string // Company name on the mandate
	Coc            string // The enterprise number (can only be changed if companyName is changed)
	CustomerNumber string // The customer number (can be added, updated or used to move a mandate)
	Language       string // language on the mandate (ISO 2 letters)
	Address        string // Address (street + number)
	City           string // City of debtor
	Zip            string // Zipcode of debtor
	Country        string // Country of debtor
	Extra          map[string]string
}

func (request *UpdateRequest) asUrlParams() string {
	params := url.Values{}
	addIfExists(params, "mndtId", request.MandateNumber)
	addIfExists(params, "state", request.State)
	addIfExists(params, "customerNumber", request.CustomerNumber)
	addIfExists(params, "email", request.Email)
	addIfExists(params, "mobile", request.Mobile)
	addIfExists(params, "l", request.Language)
	addIfExists(params, "lastname", request.Lastname)
	addIfExists(params, "firstname", request.Firstname)
	addIfExists(params, "contractNumber", request.ContractNumber)
	addIfExists(params, "companyName", request.CompanyName)
	addIfExists(params, "coc", request.Coc)
	addIfExists(params, "address", request.Address)
	addIfExists(params, "city", request.City)
	addIfExists(params, "zip", request.Zip)
	addIfExists(params, "country", request.Country)
	addIfExists(params, "iban", request.Iban)
	addIfExists(params, "bic", request.Bic)
	if request.Extra != nil {
		for k, v := range request.Extra {
			addIfExists(params, k, v)
		}
	}
	return params.Encode()
}

func (request *UpdateRequest) Add(key string, value string) {
	request.Extra[key] = value
}

// CtctDtls contains all contact details for a specific document
type CtctDtls struct {
	EmailAdr string
	MobNb    string
	Othr     string
}

// PstlAdr contains address data for a specific document
type PstlAdr struct {
	AdrLine string
	PstCd   string
	TwnNm   string
	Ctry    string
}

// Prty contains party details for a specific document
type Prty struct {
	Nm       string
	PstlAdr  PstlAdr
	Id       string
	CtctDtls CtctDtls
}

// KeyValue key value pairs of extra data in a document
type KeyValue struct {
	Key   string
	Value interface{}
}

type FinInstnId struct {
	BICFI string
}

type DbtrAgt struct {
	FinInstnId FinInstnId
}

type Mndt struct {
	MndtId      string
	Dbtr        Prty
	DbtrAcct    string
	DbtrAgt     DbtrAgt
	RfrdDoc     string
	SplmtryData []KeyValue
}

type MndtDetail struct {
	State       string
	Collectable bool
	Mndt        Mndt
}

// AmdmntRsn contains the reason why something was updated
type AmdmntRsn struct {
	Rsn string
}

// CxlRsn contains the reason why something was cancelled
type CxlRsn struct {
	Rsn string
}

// MandateUpdate contains all info regarding a new/update or cancelled document
type MandateUpdate struct {
	Mndt        *Mndt
	AmdmntRsn   *AmdmntRsn `json:",omitempty"`
	CxlRsn      *CxlRsn    `json:",omitempty"`
	OrgnlMndtId string
	EvtTime     string
}

// MandateUpdates is a struct to contain the response coming from Twikey, should be considered internal
type MandateUpdates struct {
	Messages []MandateUpdate
}

// DocumentInvite allows to invite a customer to sign a specific document
func (c *Client) DocumentInvite(ctx context.Context, request *InviteRequest) (*Invite, error) {

	if request.Template == "" {
		return nil, errors.New("A template is required")
	}

	params := request.asUrlParams()
	c.Debug.Debugf("New document %s", params)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/creditor/invite", strings.NewReader(params))

	var invite Invite
	if err := c.sendRequest(ctx, req, &invite); err != nil {
		return nil, err
	}
	return &invite, nil
}

// DocumentSign allows a customer to sign directly a specific document
func (c *Client) DocumentSign(ctx context.Context, request *InviteRequest) (*Invite, error) {

	if request.Template == "" {
		return nil, errors.New("A template is required")
	}

	params := request.asUrlParams()
	c.Debug.Debugf("New sign document %s", params)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/creditor/sign", strings.NewReader(params))

	var invite Invite
	if err := c.sendRequest(ctx, req, &invite); err != nil {
		return nil, err
	}
	return &invite, nil
}

// DocumentUpdate allows to update a previously added document
func (c *Client) DocumentUpdate(ctx context.Context, request *UpdateRequest) error {

	if request.MandateNumber == "" {
		return NewTwikeyError("err_invalid_mandatenumber", "A mndtId is required", "")
	}

	c.Debug.Debugf("Update document %s : %s", request.MandateNumber, request.asUrlParams())

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/creditor/mandate/update", strings.NewReader(request.asUrlParams()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", c.apiToken)
	req.Header.Add("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	err := c.sendRequest(ctx, req, nil)
	if err != nil {
		return err
	}
	return nil
}

// DocumentCancel allows to cancel (or delete if unsigned) a previously added document
func (c *Client) DocumentCancel(ctx context.Context, mandate string, reason string) error {

	if mandate == "" {
		return NewTwikeyError("err_invalid_mandatenumber", "A mandate is required", "")
	}

	params := url.Values{}
	params.Add("mndtId", mandate)
	params.Add("rsn", reason)

	c.Debug.Debugf("Cancelled document %s : %s", mandate, reason)

	req, _ := http.NewRequestWithContext(ctx, "DELETE", c.BaseURL+"/creditor/mandate?"+params.Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", c.apiToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	err := c.sendRequest(ctx, req, nil)
	return err
}

// DocumentSuspend allows to suspend/resume a signed document
func (c *Client) DocumentSuspend(ctx context.Context, mandate string, suspend bool) error {

	if mandate == "" {
		return NewTwikeyError("err_invalid_mandatenumber", "A mandate is required", "")
	}

	newState := "active"
	if suspend {
		newState = "passive"
	}

	return c.DocumentUpdate(ctx, &UpdateRequest{
		MandateNumber: mandate,
		State:         newState,
	})
}

// DocumentFeed retrieves all documents since the last call with callbacks since there may be many
func (c *Client) DocumentFeed(
	ctx context.Context,
	newDocument func(mandate *Mndt, eventTime string),
	updateDocument func(originalMandateNumber string, mandate *Mndt, reason *AmdmntRsn, eventTime string),
	cancelledDocument func(mandateNumber string, reason *CxlRsn, eventTime string)) error {

	if err := c.refreshTokenIfRequired(ctx); err != nil {
		return err
	}

	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/creditor/mandate", nil)
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", c.apiToken)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.UserAgent)

		res, err := c.HTTPClient.Do(req)
		if err != nil {
			return err
		}

		if res.StatusCode != http.StatusOK {
			return NewTwikeyErrorFromResponse(res)
		}

		payload, _ := io.ReadAll(res.Body)
		var updates MandateUpdates
		if err := json.Unmarshal(payload, &updates); err != nil {
			return err
		}

		res.Body.Close()

		c.Debug.Debugf("Fetched %d documents\n", len(updates.Messages))
		for _, update := range updates.Messages {
			if update.CxlRsn != nil {
				cancelledDocument(update.OrgnlMndtId, update.CxlRsn, update.EvtTime)
			} else if update.AmdmntRsn != nil {
				updateDocument(update.OrgnlMndtId, update.Mndt, update.AmdmntRsn, update.EvtTime)
			} else {
				newDocument(update.Mndt, update.EvtTime)
			}
		}

		if len(updates.Messages) == 0 {
			return nil
		}
	}
}

// DownloadPdf allows the download of a specific (signed) pdf
func (c *Client) DownloadPdf(ctx context.Context, mndtId string, downloadFile string) error {
	params := url.Values{}
	params.Add("mndtId", mndtId)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/creditor/mandate/pdf?"+params.Encode(), nil)
	req.Header.Add("Accept-Language", "en")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Add("Authorization", c.apiToken)

	absPath, _ := filepath.Abs(downloadFile)
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		c.Debug.Debugf("Unable to download file %s", absPath)
		return NewTwikeyErrorFromResponse(res)
	}

	payload, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	f, _ := os.Create(downloadFile)
	defer f.Close()
	if _, err := f.Write(payload); err != nil {
		c.Debug.Debugf("Unable to download file %s : %v", absPath, err)
		return err
	}

	c.Debug.Debugf("Saving to file %s", absPath)
	return nil
}

// DocumentDetail allows a snapshot of a particular mandate, note that this is rate limited.
// Force ignores the state of the mandate which is being returned
func (c *Client) DocumentDetail(ctx context.Context, mndtId string, force bool) (*MndtDetail, error) {

	if err := c.refreshTokenIfRequired(ctx); err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add("mndtId", mndtId)
	if force {
		params.Add("force", "1")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/creditor/mandate/detail?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept-Language", "en")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Add("Authorization", c.apiToken)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, NewTwikeyErrorFromResponse(res)
	}

	payload, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var mndt MndtDetail
	if err := json.Unmarshal(payload, &mndt); err != nil {
		return nil, err
	}

	mndt.State = res.Header.Get("X-STATE")
	mndt.Collectable = res.Header.Get("X-COLLECTABLE") == "true"
	return &mndt, nil
}
