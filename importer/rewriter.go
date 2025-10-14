package importer

import (
	"fmt"
	"reflect"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"gitlab.alpinelinux.org/alpine/security/secfixes-tracker/secfixes"
)

type RewriterEnv struct {
	Vendor   string   `expr:"vendor"`
	Product  string   `expr:"product"`
	TargetSW string   `expr:"target_sw"`
	Version  string   `expr:"version"`
	Cpe      CPE23Uri `expr:"cpe"`
}

type compiledRewriter struct {
	Predicate   *vm.Program
	RewriteRule *vm.Program
	Field       string
}

func NewCompiledRewriter(r secfixes.Rewriter) (cr compiledRewriter, err error) {
	genericOpts := []expr.Option{
		expr.Env(RewriterEnv{}),
		expr.Function(
			"fmt",
			exprFmt,
			new(func(string, string) string),
			new(func([]any, string) string),
		),
	}

	if r.Field != "" {
		cr.Field = r.Field
	} else {
		cr.Field = "product"
	}

	predicateOpts := append(genericOpts,
		expr.AsBool(),
	)
	cr.Predicate, err = expr.Compile(r.Predicate, predicateOpts...)
	if err != nil {
		return cr, fmt.Errorf("error compiling predicate: %w", err)
	}

	rewriterOpts := append(genericOpts,
		expr.AsKind(reflect.String),
	)
	cr.RewriteRule, err = expr.Compile(r.RewriteRule, rewriterOpts...)
	if err != nil {
		return cr, fmt.Errorf("error compiling rewrite rule: %w", err)
	}

	return cr, err
}

func (c compiledRewriter) Rewrite(cpe CPE23Uri) CPE23Uri {
	env := RewriterEnv{
		Vendor:   cpe.Vendor,
		Product:  cpe.Product,
		TargetSW: cpe.TargetSw,
		Version:  cpe.Version,
		Cpe:      cpe,
	}
	predicate, _ := expr.Run(c.Predicate, env)
	if !predicate.(bool) {
		return cpe
	}
	result, _ := expr.Run(c.RewriteRule, env)
	resultStr := result.(string)
	switch c.Field {
	case "product":
		cpe.Product = resultStr
	case "vendor":
		cpe.Vendor = resultStr
	case "version":
		cpe.Version = resultStr
	case "target_sw":
		cpe.TargetSw = resultStr
	}

	return cpe
}

// exprFmt is an implementation of sprintf for expr. It takes the thing to be
// formatted as the first argument to make it possible to use with pipes. The
// first argument can either be a string, or a list of any value.
func exprFmt(params ...any) (any, error) {
	switch arg1 := params[0].(type) {
	case string:
		return fmt.Sprintf(params[1].(string), arg1), nil
	case []any:
		return fmt.Sprintf(params[1].(string), arg1...), nil
	default:
		return "", fmt.Errorf("unsupported type for argument 1: %T", arg1)
	}
}
