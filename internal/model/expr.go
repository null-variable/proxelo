package model

import (
	"fmt"
	"sync"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"
	exprv1 "github.com/null-variable/proxelo-api/gen/go/proxelo/expr/v1"
)

// exprEnv is the CEL environment of route expressions: `request` is a
// proxelo.expr.v1.Request, with the standard library and the network
// extension. The proxy evaluates the same expressions with the same library;
// Go only type-checks them.
var exprEnv = sync.OnceValues(func() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Types(&exprv1.Request{}),
		cel.Variable("request", cel.ObjectType("proxelo.expr.v1.Request")),
		ext.Network(),
	)
})

// CheckExpr parses and type-checks a route expression, which must be a bool.
func CheckExpr(src string) error {
	env, err := exprEnv()
	if err != nil {
		return err
	}
	ast, iss := env.Compile(src)
	if iss.Err() != nil {
		return iss.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return fmt.Errorf("must be a bool expression, not %s", ast.OutputType())
	}
	return nil
}
