package service

type Options struct {
	afterStart []func() error
	afterStop  []func()
}

type Option func(*Options)

func WithAfterStart(f func() error) Option {
	return func(opts *Options) {
		opts.afterStart = append(opts.afterStart, f)
	}
}

func WithAfterStop(f func()) Option {
	return func(opts *Options) {
		opts.afterStop = append(opts.afterStop, f)
	}
}
