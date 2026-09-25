package search

import (
	"net/http"
	"net/url"
)

type Searcher interface {
	Repositories(Query) (RepositoriesResult, error)
	Issues(Query) (IssuesResult, error)
}

type searcher struct {
	client *http.Client
	host   string
}

func NewSearcher(client *http.Client, host string) Searcher {
	return &searcher{client: client, host: host}
}

func (s searcher) Repositories(query Query) (RepositoriesResult, error) {
	result := RepositoriesResult{}
	_, err := s.search(query, &result)
	return result, err
}

func (s searcher) Issues(query Query) (IssuesResult, error) {
	result := IssuesResult{}
	_, err := s.search(query, &result)
	return result, err
}

func (s searcher) search(query Query, result interface{}) (*http.Response, error) {
	values := url.Values{}
	values.Set("q", query.String())
	request, err := http.NewRequest("GET", "https://"+s.host+"/search/"+query.Kind+"?"+values.Encode(), nil)
	if err != nil {
		return nil, err
	}
	return s.client.Do(request)
}
