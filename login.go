package login

import (
	"fmt"
	"strings"

	"github.com/thrisp/flotilla"
	"github.com/thrisp/flotilla/session"
)

type (
	handlers map[string]flotilla.Manage

	Manager struct {
		s          session.SessionStore
		userloader func(string) User
		App        *flotilla.App
		Settings   map[string]string
		Handlers   map[string]flotilla.Manage
	}
)

var (
	defaultsettings map[string]string = map[string]string{
		"COOKIE_NAME":          "remember_token",
		"COOKIE_DURATION":      "31",
		"COOKIE_PATH":          "/",
		"MESSAGE_CATEGORY":     "message",
		"REFERESH_MESSAGE":     "Please reauthenticate to access this page.",
		"UNAUTHORIZED_MESSAGE": "Please log in to access this page",
	}
)

func New(c ...Configuration) *Manager {
	m := &Manager{Settings: defaultsettings,
		Handlers: make(handlers)}
	c = append(c, Handler("cookie", m.GetRemembered))
	err := m.Configuration(c...)
	if err != nil {
		panic(fmt.Sprintf("[FLOTILLA-LOGIN] configuration error: %s", err))
	}
	return m
}

func loginctxfuncs(m *Manager) map[string]interface{} {
	ret := make(map[string]interface{})
	ret["loginmanager"] = func(c *flotilla.Ctx) *Manager { m.Reload(c); return m }
	ret["currentuser"] = func(c *flotilla.Ctx) User { return currentuser(c) }
	return ret
}

func (m *Manager) Init(app *flotilla.App) {
	m.App = app
	app.Configuration = append(app.Configuration,
		flotilla.Extensions(loginctxfuncs(m)),
		flotilla.CtxProcessor("CurrentUser", currentuser))
	app.Use(m.UpdateRemembered)
}

func (m *Manager) reloaders() []flotilla.Manage {
	ret := []flotilla.Manage{}
	for _, rl := range []string{"cookie", "request", "token", "header"} {
		if h, ok := m.Handlers[rl]; ok {
			ret = append(ret, h)
		}
	}
	return ret
}

func (m *Manager) Reload(c *flotilla.Ctx) {
	m.s = c.Session
	if uid := m.s.Get("user_id"); uid != nil {
		for _, fn := range m.reloaders() {
			fn(c)
		}
	}
}

func (m *Manager) Setting(key string) string {
	if item, ok := m.App.Env.Store[storekey(key)]; ok {
		return item.Value
	}
	if item, ok := m.Settings[strings.ToUpper(key)]; ok {
		return item
	}
	return ""
}

func (m *Manager) currentuserid() string {
	if uid := m.s.Get("user_id"); uid != nil {
		return uid.(string)
	}
	return ""
}

func currentuser(c *flotilla.Ctx) User {
	return manager(c).CurrentUser()
}

func (m *Manager) CurrentUser() User {
	if usr := m.s.Get("user"); usr == nil {
		m.reloaduser()
	}
	user := m.s.Get("user")
	return user.(User)
}

func (m *Manager) LoginUser(user User, remember bool, fresh bool) bool {
	if !user.IsActive() {
		return false
	}
	m.s.Set("user_id", user.GetId())
	m.s.Set("_fresh", fresh)
	m.s.Set("user", user)
	if remember {
		m.s.Set("remember", "set")
	}
	return true
}

func (m *Manager) LogoutUser() bool {
	m.s.Delete("user")
	m.s.Delete("user_id")
	m.s.Set("remember", "clear")
	m.reloaduser()
	return true
}

func (m *Manager) UserLoader(userid string) User {
	if u := m.userloader; u != nil {
		return u(userid)
	}
	return &AnonymousUser{}
}

func (m *Manager) reloaduser() {
	m.loaduser(m.currentuserid())
}

func (m *Manager) loaduser(userid string) {
	m.s.Set("user", m.UserLoader(userid))
}

func (m *Manager) Unauthenticated(c *flotilla.Ctx) {
	c.Flash(m.Setting("message_category"), m.Setting("unauthenticated_message"))
	if h := m.Handlers["unauthenticated"]; h != nil {
		h(c)
	}
	if loginurl := m.Setting("login_url"); loginurl != "" {
		c.Redirect(303, loginurl)
	} else {
		c.Status(401)
	}
}

func manager(c *flotilla.Ctx) *Manager {
	m, _ := c.Call("loginmanager", c)
	return m.(*Manager)
}

// RequireLogin is a flotilla HandlerFunc that checks for authorized user,
// aborting with 401 if unauthenticated.
func RequireLogin(c *flotilla.Ctx) {
	m := manager(c)
	currentuser := m.CurrentUser()
	if !currentuser.IsAuthenticated() {
		m.Unauthenticated(c)
	}
}

// LoginRequired wraps a flotilla HandlerFunc to ensure that the current
// user is logged in and authenticated before calling the handlerfunc.
func LoginRequired(h flotilla.Manage) flotilla.Manage {
	return func(c *flotilla.Ctx) {
		m := manager(c)
		if m.CurrentUser().IsAuthenticated() {
			h(c)
		} else {
			m.Unauthenticated(c)
		}
	}
}

func (m *Manager) NeedsRefresh() bool {
	if fresh := m.s.Get("_fresh"); fresh != nil {
		return !fresh.(bool)
	}
	return true
}

func (m *Manager) Refresh(c *flotilla.Ctx) {
	if h := m.Handlers["refresh"]; h != nil {
		h(c)
	} else {
		c.Flash(m.Setting("message_category"), m.Setting("refresh_message"))
		if refreshurl := m.Setting("refresh_url"); refreshurl != "" {
			c.Redirect(303, refreshurl)
		} else {
			c.Status(403)
		}
	}
}

func RefreshRequired(h flotilla.Manage) flotilla.Manage {
	return func(c *flotilla.Ctx) {
		m := manager(c)
		if m.NeedsRefresh() {
			m.Refresh(c)
		} else {
			h(c)
		}
	}
}

func (m *Manager) SetRemembered(c *flotilla.Ctx) {
	name := m.Setting("COOKIE_NAME")
	value := c.Session.Get("user_id").(string)
	duration := cookieseconds(m.Setting("COOKIE_DURATION"))
	path := m.Setting("COOKIE_PATH")
	c.SecureCookie(name, value, duration, path)
}

func (m *Manager) GetRemembered(c *flotilla.Ctx) {
	if cookie, ok := c.ReadCookies()[m.Setting("COOKIE_NAME")]; ok {
		c.Session.Set("user_id", cookie)
		c.Session.Set("_fresh", false)
		m.reloaduser()
	}
}

func (m *Manager) UpdateRemembered(c *flotilla.Ctx) {
	c.Next()
	if remember := c.Session.Get("remember"); remember != nil {
		switch remember.(string) {
		case "set":
			m.SetRemembered(c)
		case "clear":
			m.ClearRemembered(c)
		}
		c.Session.Delete("remember")
	}
}

func (m *Manager) ClearRemembered(c *flotilla.Ctx) {
	name, value, path := m.Setting("COOKIE_NAME"), "", m.Setting("COOKIE_PATH")
	c.SecureCookie(name, value, 0, path)
}
