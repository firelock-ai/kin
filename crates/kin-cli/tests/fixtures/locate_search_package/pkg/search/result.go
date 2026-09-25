package search

type RepositoriesResult struct {
	Items []Repository
	Total int
}

type IssuesResult struct {
	Items []Issue
	Total int
}

type Repository struct {
	FullName string
	Stars    int
}

type Issue struct {
	Number int
	Title  string
}
