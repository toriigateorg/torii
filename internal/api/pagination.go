package api

import (
	"strconv"

	"github.com/labstack/echo/v5"
)

const (
	defaultPageSize = 20
	maxPageSize     = 100
)

type pageMeta struct {
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
	Total    int64 `json:"total"`
}

func parsePagination(c *echo.Context) (limit int32, offset int32, page int, pageSize int) {
	page = atoiDefault(c.QueryParam("page"), 1)
	if page < 1 {
		page = 1
	}
	pageSize = atoiDefault(c.QueryParam("page_size"), defaultPageSize)
	if pageSize < 1 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	limit = int32(pageSize)
	offset = int32((page - 1) * pageSize)
	return
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}
