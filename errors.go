package twikey

import "net/http"

type TwikeyError struct {
	Status  int
	Code    string
	Message string
	Extra   string
}

func (err *TwikeyError) Error() string {
	return err.Message
}

func (err *TwikeyError) IsUserError() bool {
	return err.Status == 400
}

func NewTwikeyError(code string, msg string, extra string) *TwikeyError {
	return &TwikeyError{
		Status:  400,
		Code:    code,
		Message: msg,
		Extra:   extra,
	}
}

func NewTwikeyErrorFromResponse(res *http.Response) *TwikeyError {
	if res.StatusCode == 400 {
		errcode := res.Header["Apierror"][0]
		return &TwikeyError{
			Status:  res.StatusCode,
			Code:    errcode,
			Message: errcode,
		}
	}
	return &TwikeyError{
		Status:  res.StatusCode,
		Code:    "system_error",
		Message: res.Status,
	}
}
