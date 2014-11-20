package login

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/thrisp/flotilla"
)

type (
	LoginManager struct {
		ctx                 *flotilla.Ctx
		App                 *flotilla.App
		defaultconfig       map[string]string
		UserLoader          func(string) User
		UnauthorizedHandler flotilla.HandlerFunc
	}
)

func New() *LoginManager {
	return &LoginManager{defaultconfig: defaultconfig()}
}

func loginctxfuncs(l *LoginManager) map[string]interface{} {
	ret := make(map[string]interface{})
	ret["loginmanager"] = func(c *flotilla.Ctx) *LoginManager { l.Reload(c); return l }
	return ret
}

func defaultconfig() map[string]string {
	ret := make(map[string]string)
	ret["COOKIE_NAME"] = "remember_token"
	ret["COOKIE_DURATION"] = "31"
	ret["MESSAGE_CATEGORY"] = "message"
	ret["REFRESH_MESSAGE"] = "Please reauthenticate to access this page."
	ret["UNAUTHORIZED_MESSAGE"] = "Please log in to access this page"
	return ret
}

func (l *LoginManager) Init(app *flotilla.App) {
	l.App = app
	// add ctxprocessor to access current_user in template
	app.Configuration = append(app.Configuration, flotilla.CtxFuncs(loginctxfuncs(l)))
	app.Use(l.updateremembered)
}

func (l *LoginManager) Reload(c *flotilla.Ctx) {
	l.ctx = c
	if uid := l.ctx.Session.Get("user_id"); uid == nil {
		l.loadremembered()
	}
}

func storekey(key string) string {
	return fmt.Sprintf("LOGIN_%s", strings.ToUpper(key))
}

func (l *LoginManager) config(key string) string {
	//if item, ok := l.ctx.App.Env.Store[storekey(key))]; ok {
	//	return item.Value
	//}
	if item, ok := l.defaultconfig[strings.ToUpper(key)]; ok {
		return item
	}
	return ""
}

func (l *LoginManager) currentuserid() string {
	uid := l.ctx.Session.Get("user_id")
	if uid != nil {
		return uid.(string)
	}
	return ""
}

func (l *LoginManager) CurrentUser() User {
	return l.getuser()
}

func (l *LoginManager) LoginUser(user User, remember bool) bool {
	if !user.IsActive() {
		return false
	}
	l.ctx.Session.Set("user_id", user.GetId())
	l.ctx.Session.Set("_fresh", true)
	if remember {
		l.ctx.Session.Set("remember", "set")
	}
	l.ctx.Set("user", user)
	return true
}

func (l *LoginManager) LogoutUser() bool {
	l.unloaduser()
	return true
}

func (l *LoginManager) getuser() User {
	if l.ctx != nil {
		if _, ok := l.ctx.Data["user"]; !ok {
			l.loaduser()
		}
		user, _ := l.ctx.Get("user")
		return user.(User)
	}
	return nil
}

func (l *LoginManager) loaduser() {
	l.reloaduser(l.currentuserid())
}

func (l *LoginManager) reloaduser(userid string) {
	l.ctx.Set("user", l.UserLoader(userid))
}

func (l *LoginManager) unloaduser() {
	l.ctx.Set("user", nil)
	l.ctx.Session.Delete("user_id")
	l.ctx.Session.Set("remember", "clear")
	l.loaduser()
}

func (l *LoginManager) unauthorized() error {
	if l.UnauthorizedHandler != nil {
		l.UnauthorizedHandler(l.ctx)
	}
	l.ctx.Flash(l.config("message_category"), l.config("unauthorized_message"))
	if lv := l.config("login_url"); lv != "" {
		l.ctx.Redirect(401, lv)
	} else {
		l.ctx.Status(401)
	}
	return nil
}

func (l *LoginManager) updateremembered(c *flotilla.Ctx) {
	c.Next()
	if remember := c.Session.Get("remember"); remember != nil {
		switch remember.(string) {
		case "set":
			l.setremembered()
		case "clear":
			l.clearremembered()
		}
		c.Session.Delete("remember")
	}
}

func (l *LoginManager) loadremembered() {
	if x, ok := l.ctx.ReadCookies()[l.config("COOKIE_NAME")]; ok {
		fmt.Printf("remember_cookie: %+v\n", x)
		//update session user_id from remember_token
		l.ctx.Session.Set("_fresh", false)
	}
}

func cookieseconds(d string) int {
	base, err := strconv.Atoi(d)
	if err != nil {
		base = 31
	}
	return int((time.Duration(base*24) * time.Hour) / time.Second)
}

func (l *LoginManager) setremembered() {
	cookiename := l.config("COOKIE_NAME")
	cookievalue := l.ctx.Session.Get("user_id").(string)
	cookieduration := cookieseconds(l.config("COOKIE_DURATION"))
	l.ctx.SecureCookie(cookiename, cookievalue, cookieduration)
	//fmt.Printf("set remember cookie: %s %s %d\n", cookiename, cookievalue, cookieduration)
}

func (l *LoginManager) clearremembered() {
	cookiename := l.config("COOKIE_NAME")
	cookievalue := ""
	l.ctx.SecureCookie(cookiename, cookievalue, 0)
	//fmt.Printf("clear remember cookie\n")
}

// RequireLogin is a flotilla HandlerFunc that checks for authorized user,
// aborting with 401 if unauthorized.
func RequireLogin(c *flotilla.Ctx) {
	l, _ := c.Call("loginmanager", c)
	m := l.(*LoginManager)
	currentuser := m.CurrentUser()
	if !currentuser.IsAuthenticated() {
		m.unauthorized()
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
			m.unauthorized()
		}
	}
}

//func RefreshRequired(h flotilla.HandlerFunc) flotilla.HandlerFunc {
//	return func(c *flotilla.Ctx) {}
