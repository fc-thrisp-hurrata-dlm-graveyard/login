package login

import (
	"fmt"
	"strings"

	"github.com/thrisp/flotilla"
	"github.com/thrisp/flotilla/session"
)

type (
	handlers map[string]flotilla.HandlerFunc

	LoginManager struct {
		s          session.SessionStore
		userloader func(string) User
		App        *flotilla.App
		Env        map[string]string
		Handlers   map[string]flotilla.HandlerFunc
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

func New(c ...Configuration) *LoginManager {
	l := &LoginManager{Env: defaultsettings,
		Handlers: make(handlers)}
	c = append(c, Handler("cookie", l.Getremembered))
	err := l.Configuration(c...)
	if err != nil {
		panic(fmt.Sprintf("[FLOTILLA-LOGIN] configuration error: %s", err))
	}
	return l
}

func loginctxfuncs(l *LoginManager) map[string]interface{} {
	ret := make(map[string]interface{})
	ret["loginmanager"] = func(c *flotilla.Ctx) *LoginManager { l.Reload(c); return l }
	ret["currentuser"] = func(c *flotilla.Ctx) User { return currentuser(c) }
	return ret
}

func (l *LoginManager) Init(app *flotilla.App) {
	l.App = app
	app.Configuration = append(app.Configuration,
		flotilla.CtxFuncs(loginctxfuncs(l)),
		flotilla.CtxProcessor("CurrentUser", currentuser))
	app.Use(l.Updateremembered)
}

func (l *LoginManager) reloaders() []flotilla.HandlerFunc {
	ret := []flotilla.HandlerFunc{}
	for _, rl := range []string{"cookie", "request", "token", "header"} {
		if h, ok := l.Handlers[rl]; ok {
			ret = append(ret, h)
		}
	}
	return ret
}

func (l *LoginManager) Reload(c *flotilla.Ctx) {
	l.s = c.Session
	if uid := l.s.Get("user_id"); uid != nil {
		for _, fn := range l.reloaders() {
			fn(c)
		}
	}
}

func (l *LoginManager) Setting(key string) string {
	if item, ok := l.App.Env.Store[storekey(key)]; ok {
		return item.Value
	}
	if item, ok := l.Env[strings.ToUpper(key)]; ok {
		return item
	}
	return ""
}

func (l *LoginManager) currentuserid() string {
	if uid := l.s.Get("user_id"); uid != nil {
		return uid.(string)
	}
	return ""
}

func currentuser(c *flotilla.Ctx) User {
	l, _ := c.Call("loginmanager", c)
	m := l.(*LoginManager)
	return m.CurrentUser()
}

func (l *LoginManager) CurrentUser() User {
	if usr := l.s.Get("user"); usr == nil {
		l.reloaduser()
	}
	user := l.s.Get("user")
	return user.(User)
}

func (l *LoginManager) LoginUser(user User, remember bool, fresh bool) bool {
	if !user.IsActive() {
		return false
	}
	l.s.Set("user_id", user.GetId())
	l.s.Set("_fresh", fresh)
	l.s.Set("user", user)
	if remember {
		l.s.Set("remember", "set")
	}
	return true
}

func (l *LoginManager) LogoutUser() bool {
	l.s.Delete("user")
	l.s.Delete("user_id")
	l.s.Set("remember", "clear")
	l.reloaduser()
	return true
}

func (l *LoginManager) UserLoader(userid string) User {
	if u := l.userloader; u != nil {
		return u(userid)
	}
	return &AnonymousUser{}
}

func (l *LoginManager) reloaduser() {
	l.loaduser(l.currentuserid())
}

func (l *LoginManager) loaduser(userid string) {
	l.s.Set("user", l.UserLoader(userid))
}

func (l *LoginManager) Unauthorized(c *flotilla.Ctx) {
	c.Flash(l.Setting("message_category"), l.Setting("unauthorized_message"))
	if h := l.Handlers["unauthorized"]; h != nil {
		h(c)
	}
	if loginurl := l.Setting("login_url"); loginurl != "" {
		c.Redirect(303, loginurl)
	} else {
		c.Status(401)
	}
}

// RequireLogin is a flotilla HandlerFunc that checks for authorized user,
// aborting with 401 if unauthorized.
func RequireLogin(c *flotilla.Ctx) {
	l, _ := c.Call("loginmanager", c)
	m := l.(*LoginManager)
	currentuser := m.CurrentUser()
	if !currentuser.IsAuthenticated() {
		m.Unauthorized(c)
	}
}

// LoginRequired wraps a flotilla HandlerFunc to ensure that the current
// user is logged in and authenticated before calling the handlerfunc.
func LoginRequired(h flotilla.HandlerFunc) flotilla.HandlerFunc {
	return func(c *flotilla.Ctx) {
		l, _ := c.Call("loginmanager", c)
		m := l.(*LoginManager)
		if m.CurrentUser().IsAuthenticated() {
			h(c)
		} else {
			m.Unauthorized(c)
		}
	}
}

func (l *LoginManager) NeedsRefresh() bool {
	if fresh := l.s.Get("_fresh"); fresh != nil {
		return !fresh.(bool)
	}
	return true
}

func (l *LoginManager) Refresh(c *flotilla.Ctx) {
	if h := l.Handlers["refresh"]; h != nil {
		h(c)
	} else {
		c.Flash(l.Setting("message_category"), l.Setting("refresh_message"))
		if refreshurl := l.Setting("refresh_url"); refreshurl != "" {
			c.Redirect(303, refreshurl)
		} else {
			c.Status(403)
		}
	}
}

func RefreshRequired(h flotilla.HandlerFunc) flotilla.HandlerFunc {
	return func(c *flotilla.Ctx) {
		l, _ := c.Call("loginmanager", c)
		m := l.(*LoginManager)
		if m.NeedsRefresh() {
			m.Refresh(c)
		} else {
			h(c)
		}
	}
}

func (l *LoginManager) Setremembered(c *flotilla.Ctx) {
	cookiename := l.Setting("COOKIE_NAME")
	cookievalue := c.Session.Get("user_id").(string)
	cookieduration := cookieseconds(l.Setting("COOKIE_DURATION"))
	cookiepath := l.Setting("COOKIE_PATH")
	c.SecureCookie(cookiename, cookievalue, cookieduration, cookiepath)
}

func (l *LoginManager) Getremembered(c *flotilla.Ctx) {
	if cookie, ok := c.ReadCookies()[l.Setting("COOKIE_NAME")]; ok {
		c.Session.Set("user_id", cookie)
		c.Session.Set("_fresh", false)
		l.reloaduser()
	}
}

func (l *LoginManager) Updateremembered(c *flotilla.Ctx) {
	c.Next()
	if remember := c.Session.Get("remember"); remember != nil {
		switch remember.(string) {
		case "set":
			l.Setremembered(c)
		case "clear":
			l.Clearremembered(c)
		}
		c.Session.Delete("remember")
	}
}

func (l *LoginManager) Clearremembered(c *flotilla.Ctx) {
	cookiename := l.Setting("COOKIE_NAME")
	cookievalue := ""
	cookiepath := l.Setting("COOKIE_PATH")
	c.SecureCookie(cookiename, cookievalue, 0, cookiepath)
}
