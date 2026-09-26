package api

import "context"

type Client struct {
	host string
}

func (c Client) Query(hostname, name string, query interface{}, variables map[string]interface{}) error {
	return c.QueryWithContext(context.Background(), hostname, name, query, variables)
}

func (c Client) QueryWithContext(ctx context.Context, hostname, name string, query interface{}, variables map[string]interface{}) error {
	return nil
}
