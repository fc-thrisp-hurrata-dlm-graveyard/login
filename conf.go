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

func UserLoader(fn func(string) User) Configuration {
	return func(l *LoginManager) error {
		l.userloader = fn
		return nil
	}
}

func Handler(name string, h flotilla.HandlerFunc) Configuration {
	return func(l *LoginManager) error {
		l.Handlers[name] = h
		return nil
	}
}

func Unauthorized(h flotilla.HandlerFunc) Configuration {
	return func(l *LoginManager) error {
		l.Handlers["unauthorized"] = h
		return nil
	}
}

func Settings(items ...string) Configuration {
	return func(l *LoginManager) error {
		for _, item := range items {
			i := strings.Split(item, ":")
			key, value := i[0], i[1]
			l.Env[strings.ToUpper(key)] = value
		}
		return nil
	}
}
