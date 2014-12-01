package login

import (
	"fmt"
	"strings"

	"github.com/thrisp/flotilla"
	"github.com/thrisp/flotilla/session"
)

type (
	LoginManager struct {
		s          session.SessionStore
		App        *flotilla.App
		Env        map[string]string
		userloader func(string) User
		Handlers   map[string]flotilla.HandlerFunc
	}
)

var (
	defaultenv map[string]string = map[string]string{
		"COOKIE_NAME":          "remember_token",
		"COOKIE_DURATION":      "31",
		"COOKIE_PATH":          "/",
		"MESSAGE_CATEGORY":     "message",
		"REFERESH_MESSAGE":     "Please reauthenticate to access this page.",
		"UNAUTHORIZED_MESSAGE": "Please log in to access this page",
	}

	defaulthandlers map[string]flotilla.HandlerFunc
)

func New(c ...Configuration) *LoginManager {
	l := &LoginManager{Env: defaultenv,
		Handlers: defaulthandlers}
	err := l.Configuration(c...)
	if err != nil {
		panic(fmt.Sprintf("[FLOTILLA-LOGIN] configuration error: %s", err))
	}
	return l
}

func loginctxfuncs(l *LoginManager) map[string]interface{} {
	ret := make(map[string]interface{})
	ret["loginmanager"] = func(c *flotilla.Ctx) *LoginManager { l.Reload(c); return l }
	ret["currentuser"] = func() error { fmt.Printf("return current user"); return nil }
	return ret
}

func (l *LoginManager) Init(app *flotilla.App) {
	l.App = app
	// add ctxprocessor to access current_user in template
	app.Configuration = append(app.Configuration, flotilla.CtxFuncs(loginctxfuncs(l)))
	app.Use(l.updateremembered)
}

func (l *LoginManager) Reload(c *flotilla.Ctx) {
	l.s = c.Session
	if uid := l.s.Get("user_id"); uid == nil {
		l.loadremembered(c)
	}
}

func (l *LoginManager) env(key string) string {
	if item, ok := l.App.Env.Store[storekey(key)]; ok {
		return item.Value
	}
	if item, ok := l.Env[strings.ToUpper(key)]; ok {
		return item
	}
	return ""
}

func (l *LoginManager) currentuserid() string {
	uid := l.s.Get("user_id")
	if uid != nil {
		return uid.(string)
	}
	return ""
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
	if remember {
		l.s.Set("remember", "set")
	}
	l.s.Set("_fresh", fresh)
	l.s.Set("user", user)
	return true
}

func (l *LoginManager) LogoutUser() bool {
	l.s.Set("_test", "from LoGoUtUsEr FUNCTION")
	l.unloaduser()
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

func (l *LoginManager) unloaduser() {
	l.s.Delete("user")
	l.s.Delete("user_id")
	l.s.Set("remember", "clear")
	l.reloaduser()
}

func (l *LoginManager) Unauthorized(c *flotilla.Ctx) {
	if h := l.Handlers["unauthorized"]; h != nil {
		h(c)
	}
	c.Flash(l.env("message_category"), l.env("unauthorized_message"))
	if lv := l.env("login_url"); lv != "" {
		c.Redirect(401, lv)
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

//func RefreshRequired(h flotilla.HandlerFunc) flotilla.HandlerFunc {
//	return func(c *flotilla.Ctx) {}

func (l *LoginManager) updateremembered(c *flotilla.Ctx) {
	c.Next()
	if remember := c.Session.Get("remember"); remember != nil {
		switch remember.(string) {
		case "set":
			l.setremembered(c)
		case "clear":
			l.clearremembered(c)
		}
		c.Session.Delete("remember")
	}
}

func (l *LoginManager) loadremembered(c *flotilla.Ctx) {
	if cookie, ok := c.ReadCookies()[l.env("COOKIE_NAME")]; ok {
		c.Session.Set("user_id", cookie)
		c.Session.Set("_fresh", false)
		l.loaduser(cookie)
	}
}

func (l *LoginManager) setremembered(c *flotilla.Ctx) {
	cookiename := l.env("COOKIE_NAME")
	cookievalue := c.Session.Get("user_id").(string)
	cookieduration := cookieseconds(l.env("COOKIE_DURATION"))
	cookiepath := l.env("COOKIE_PATH")
	c.SecureCookie(cookiename, cookievalue, cookieduration, cookiepath)
}

func (l *LoginManager) clearremembered(c *flotilla.Ctx) {
	cookiename := l.env("COOKIE_NAME")
	cookievalue := ""
	cookiepath := l.env("COOKIE_PATH")
	c.SecureCookie(cookiename, cookievalue, 0, cookiepath)
}
