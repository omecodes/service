package context

type Key string

const (
	Jwt         = Key("jwt")
	Token       = Key("token")
	User        = Key("user")
	UserAgent   = Key("user-agent")
	PeerAddress = Key("peer-address")
)
