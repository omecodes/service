package authentication

type Credentials struct {
	Username string
	Password string
}

type ProxyCredentials struct {
	Key    string
	Secret string
}
