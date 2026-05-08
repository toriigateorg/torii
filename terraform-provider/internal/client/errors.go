package client

import (
	"errors"
	"fmt"
)

var ErrNotFound = errors.New("torii: resource not found")

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("torii: HTTP %d", e.Status)
	}
	return fmt.Sprintf("torii: HTTP %d: %s", e.Status, e.Message)
}

func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}
