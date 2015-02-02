package login

import (
	"strings"

	"github.com/thrisp/flotilla"
)

type (
	Configuration func(*Manager) error
)

func (l *Manager) Configuration(conf ...Configuration) error {
	var err error
	for _, c := range conf {
		err = c(l)
	}
	return err
}

func UserLoader(fn func(string) User) Configuration {
	return func(l *Manager) error {
		l.userloader = fn
		return nil
	}
}

func Handler(name string, h flotilla.Manage) Configuration {
	return func(l *Manager) error {
		l.Handlers[name] = h
		return nil
	}
}

func Unauthorized(h flotilla.Manage) Configuration {
	return func(l *Manager) error {
		l.Handlers["unauthorized"] = h
		return nil
	}
}

func Settings(items ...string) Configuration {
	return func(l *Manager) error {
		for _, item := range items {
			i := strings.Split(item, ":")
			key, value := i[0], i[1]
			l.Settings[strings.ToUpper(key)] = value
		}
		return nil
	}
}
