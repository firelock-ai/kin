package search

type Command struct {
	Use   string
	Short string
}

func NewCmdSearch() *Command {
	return &Command{Use: "search <command>", Short: "Search for repositories and issues"}
}
