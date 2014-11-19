package login

import (
	"fmt"
	"strings"

	"github.com/thrisp/flotilla"
)

type (
	LoginManager struct {
		ctx              *flotilla.Ctx
		App              *flotilla.App
		defaultconfig    map[string]string
		UserLoader       func(string) User
		UnauthorizedCall flotilla.HandlerFunc
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
	ret["MESSAGE_CATEGORY"] = "message"
	ret["REFRESH_MESSAGE"] = "Please reauthenticate to access this page."
	ret["UNAUTHORIZED_MESSAGE"] = "Please log in to access this page"
	return ret
}

// RequireLogin is a flotilla HandlerFunc that checks for authorized user,
// aborting with 401 if unauthorized.
func RequireLogin(c *flotilla.Ctx) {
	l, _ := c.Call("loginmanager", c)
	m := l.(*LoginManager)
	currentuser := m.Currentuser()
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
		currentuser := m.Currentuser()
		if currentuser.IsAuthenticated() {
			h(c)
		} else {
			m.unauthorized()
		}
	}
}

//func RefreshRequired(h flotilla.HandlerFunc) flotilla.HandlerFunc {
//return func(c *flotilla.Ctx) {
//l, _ := c.Call("loginmanager", c)
//m := l.(*LoginManager)
//currentuser := m.Currentuser()
//	if currentuser.IsAuthenticated() {
//		if rv, ok := l.Views["refresh"]; ok {
//        // flash refresh message
//        // set next as current url
//        c.Redirect(303, rv)
//      } else {
//        c.Status(403)
//      }
//	} else {
//		m.unauthorized()
//	}
//}
//}

func (l *LoginManager) Init(app *flotilla.App) {
	l.App = app
	app.Configuration = append(app.Configuration, flotilla.CtxFuncs(loginctxfuncs(l)))
}

func (l *LoginManager) Reload(c *flotilla.Ctx) {
	l.ctx = c
	if uid := l.ctx.Session.Get("user_id"); uid == nil {
		//fmt.Printf("%+v\n", l.ctx.Session.Get("user_id"))
		l.loadremembered()
		//fmt.Printf("%+v\n", l.ctx.ReadCookies())
	}
}

func (l *LoginManager) configordefault(key string) string {
	k := strings.ToUpper(key)
	//if item, ok := l.ctx.App.Env.Store[k]; ok {
	//	return item.Value
	//}
	if item, ok := l.defaultconfig[k]; ok {
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

func (l *LoginManager) Currentuser() User {
	return l.getuser()
}

func (l *LoginManager) Loginuser(user User, remember bool) bool {
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

func (l *LoginManager) Logoutuser() bool {
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
	if l.UnauthorizedCall != nil {
		l.UnauthorizedCall(l.ctx)
	}
	l.ctx.Flash(l.configordefault("unauthorized_message"), l.configordefault("message_category"))
	if lv := l.configordefault("login_url"); lv != "" {
		l.ctx.Redirect(401, lv)
	} else {
		l.ctx.Status(401)
	}
	return nil
}

func (l *LoginManager) setremembered(c *flotilla.Ctx) {
	if remember := c.Session.Get("remember"); remember != nil {
		switch remember.(string) {
		case "set":
			fmt.Printf("set remember cookie\n")
		case "clear":
			fmt.Printf("clear remember cookie\n")
		}
	}
}

func (l *LoginManager) loadremembered() {
	cookiename := l.configordefault("COOKIE_NAME")
	if x, ok := l.ctx.ReadCookies()[cookiename]; ok {
		fmt.Printf("remember_cookie: %+v\n", x)
		l.ctx.Session.Set("_fresh", false)
	}
}
