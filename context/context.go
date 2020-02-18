package context

type Key string

const (
	//Jwt            = Key("jwt")
	//Token          = Key("token")
	User = Key("user")
	//UserAgent      = Key("user-agent")
	//PeerAddress    = Key("peer-address")
	ServiceContext = Key("service-context")

	AuthorizationToken    = Key("Authorization-Token")
	StrAuthorizationToken = Key("St-Authorization-Token")
	Credentials           = Key("Credentials")
)
