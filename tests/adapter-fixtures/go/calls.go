// Fixture for Go call-resolution tests.
// Covers plain calls, package-qualified calls, receiver-method calls,
// and chained method calls. The parser must emit simple-name Calls
// edges (e.g. "Println" rather than "fmt.Println").
package calls

import "fmt"

type Server struct{}

func (s *Server) Run() {}

func (s *Server) B() *Server { return s }

func (s *Server) C() {}

func plain() {}

func Caller() {
	plain()
	fmt.Println("x")
	s := &Server{}
	s.Run()
	s.B().C()
}
