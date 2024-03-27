package twikey

import (
	"context"
	"errors"
	"net/http"
)

func (c *Client) CustomerUpdate(ctx context.Context, request *Customer) error {

	if request.CustomerNumber == "" {
		return errors.New("A customerNumber is required")
	}

	params := request.asUrlParams()
	c.Debug.Debugf("Update customer %s", params)

	req, _ := http.NewRequestWithContext(ctx, "PATCH", c.BaseURL+"/customer/"+request.CustomerNumber+"?"+params, nil)
	if err := c.sendRequest(ctx, req, nil); err != nil {
		return err
	}
	return nil
}
