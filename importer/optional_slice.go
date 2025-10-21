package importer

import "github.com/moznion/go-optional"

// OptionalFirst returns an option.Some with the first element of a slice if
// available, otherwise an optional.None.
func OptionalFirst[S ~[]E, E any](s S) optional.Option[E] {
	if len(s) > 0 {
		return optional.Some(s[0])
	} else {
		return optional.None[E]()
	}
}

// OptionalNonEmpty returns optional.Some if the provided slice contains any
// elements, otherwise optional.None
func OptionalNonEmpty[S ~[]E, E any](s S) optional.Option[S] {
	if len(s) > 0 {
		return optional.Some(s)
	} else {
		return optional.None[S]()
	}
}
