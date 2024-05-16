package secfixes

type Rewriter struct {
	Field       string
	Predicate   string
	RewriteRule string `toml:"rewrite_rule"`
}
