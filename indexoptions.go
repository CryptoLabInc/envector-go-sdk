package envector

type indexOptions struct {
	Name        string
	Keys        *Keys
	Description string
}

// IndexOption configures Client.Index. Apply via the With* helpers below.
// WithIndexName is required. WithIndexKeys is required when creating a new
// index (dim is sourced from Keys.Dim()) and when calling Insert; Score
// uses it only for early-fail dim validation.
type IndexOption func(*indexOptions)

func WithIndexName(n string) IndexOption        { return func(o *indexOptions) { o.Name = n } }
func WithIndexKeys(k *Keys) IndexOption         { return func(o *indexOptions) { o.Keys = k } }
func WithIndexDescription(s string) IndexOption { return func(o *indexOptions) { o.Description = s } }
