package login

import (
	"strings"

	"github.com/thrisp/flotilla"
)

type (
	Configuration func(*LoginManager) error
)

func (l *LoginManager) Configuration(conf ...Configuration) error {
	var err error
	for _, c := range conf {
		err = c(l)
	}
	return err
}

func UserLoader(f func(string) User) Configuration {
	return func(l *LoginManager) error {
		l.userloader = f
		return nil
	}
}

func Unauthorized(h flotilla.HandlerFunc) Configuration {
	return func(l *LoginManager) error {
		l.Handlers["unauthorized"] = h
		return nil
	}
}

func Env(items ...string) Configuration {
	return func(l *LoginManager) error {
		for _, item := range items {
			i := strings.Split(item, ":")
			key, value := i[0], i[1]
			l.Env[strings.ToUpper(key)] = value
		}
		return nil
	}
}
