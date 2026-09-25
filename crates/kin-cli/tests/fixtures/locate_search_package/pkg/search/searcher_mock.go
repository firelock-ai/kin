package search

type SearcherMock struct {
	RepositoriesFunc func(query Query) (RepositoriesResult, error)
	IssuesFunc       func(query Query) (IssuesResult, error)
}

func (mock *SearcherMock) Repositories(query Query) (RepositoriesResult, error) {
	return mock.RepositoriesFunc(query)
}

func (mock *SearcherMock) Issues(query Query) (IssuesResult, error) {
	return mock.IssuesFunc(query)
}
