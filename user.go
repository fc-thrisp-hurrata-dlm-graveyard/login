package login

type (
	User interface {
		IsAuthenticated() bool
		IsActive() bool
		IsAnonymous() bool
		GetId() string
	}

	AnonymousUser struct{}
)

func (a AnonymousUser) IsAuthenticated() bool {
	return false
}

func (a AnonymousUser) IsActive() bool {
	return false
}

func (a AnonymousUser) IsAnonymous() bool {
	return true
}

func (a AnonymousUser) GetId() string {
	return ""
}
