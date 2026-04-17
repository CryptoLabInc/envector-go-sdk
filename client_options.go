package envector

import "time"

const (
	defaultDialTimeout      = 3 * time.Second
	defaultKeepaliveTime    = 30 * time.Second
	defaultKeepaliveTimeout = 10 * time.Second
	defaultMaxMsgSize       = 100 * 1024 * 1024
)

type clientOptions struct {
	Address          string
	AccessToken      string
	Insecure         bool
	DialTimeout      time.Duration
	KeepaliveTime    time.Duration
	KeepaliveTimeout time.Duration
	MaxMsgSize       int
}

func defaultClientOptions() clientOptions {
	return clientOptions{
		DialTimeout:      defaultDialTimeout,
		KeepaliveTime:    defaultKeepaliveTime,
		KeepaliveTimeout: defaultKeepaliveTimeout,
		MaxMsgSize:       defaultMaxMsgSize,
	}
}

type ClientOption func(*clientOptions)

func WithAddress(addr string) ClientOption {
	return func(o *clientOptions) { o.Address = addr }
}

func WithAccessToken(token string) ClientOption {
	return func(o *clientOptions) { o.AccessToken = token }
}

func WithInsecure() ClientOption {
	return func(o *clientOptions) { o.Insecure = true }
}

func WithDialTimeout(d time.Duration) ClientOption {
	return func(o *clientOptions) { o.DialTimeout = d }
}

func WithKeepaliveTime(d time.Duration) ClientOption {
	return func(o *clientOptions) { o.KeepaliveTime = d }
}

func WithKeepaliveTimeout(d time.Duration) ClientOption {
	return func(o *clientOptions) { o.KeepaliveTimeout = d }
}

func WithMaxMsgSize(n int) ClientOption {
	return func(o *clientOptions) { o.MaxMsgSize = n }
}
