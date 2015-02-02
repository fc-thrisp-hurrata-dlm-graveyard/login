package login

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thrisp/flotilla"
)

type Tuser struct {
	username string
	active   bool
}

func (u *Tuser) IsAuthenticated() bool {
	return true
}

func (u *Tuser) IsActive() bool {
	return u.active
}

func (u *Tuser) IsAnonymous() bool {
	return false
}

func (u *Tuser) GetId() string {
	return u.username
}

var tusers map[string]*Tuser = map[string]*Tuser{"one": &Tuser{username: "User_One", active: true},
	"two": &Tuser{username: "User_Two"}}

func InMemoryUserLoader(s string) User {
	if u, ok := tusers[s]; ok {
		return u
	}
	return &AnonymousUser{}
}

func PerformRequest(r http.Handler, method, path string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func basemanager(c ...Configuration) *Manager {
	c = append(c, UserLoader(InMemoryUserLoader))
	l := New(c...)
	return l
}

func testhandler(c *flotilla.Ctx) {
	//passed := true
	//l, _ := c.Call("loginmanager", c)
	//m := l.(*Manager)
	//uid := m.currentuserid()
	//cu := m.CurrentUser()
	//fmt.Printf("%+v %+v\n", uid, cu)
}

func testapp(name string, m *Manager) *flotilla.App {
	f := flotilla.New(name)
	m.Init(f)
	f.Configure(f.Configuration...)
	return f
}

func TestExtension(t *testing.T) {
	exists := false
	f := testapp("test-extension", basemanager())
	f.GET("/test", func(c *flotilla.Ctx) {
		l, _ := c.Call("loginmanager", c)
		if _, ok := l.(*Manager); ok {
			exists = true
		}
		c.ServePlain(200, []byte("success"))
	})
	PerformRequest(f, "GET", "/test")
	if !exists {
		t.Errorf("login extension does not exist")
	}
}

func TestLoginRequired(t *testing.T) {
	f := testapp("test-loginrequired", basemanager())
	f.GET("/loginrequired", LoginRequired(testhandler))
	r := PerformRequest(f, "GET", "/loginrequired")
	if r.Code != http.StatusUnauthorized {
		t.Errorf("LoginRequired: status code should be %v, was %d", http.StatusUnauthorized, r.Code)
	}
}

func TestRequireLogin(t *testing.T) {
	f := testapp("test-requirelogin", basemanager())
	f.UseAt(0, RequireLogin)
	f.GET("/requirelogin", testhandler)
	r := PerformRequest(f, "GET", "/requirelogin")
	if r.Code != http.StatusUnauthorized {
		t.Errorf("Status code should be %v, was %d", http.StatusUnauthorized, r.Code)
	}
}

func TestLogin(t *testing.T) {
	loggedin := false
	f := testapp("test-login", basemanager())
	f.POST("/login", func(c *flotilla.Ctx) {
		l, _ := c.Call("loginmanager", c)
		m := l.(*Manager)
		u := tusers["one"]
		m.LoginUser(u, true, true)
		if id := m.CurrentUser().GetId(); id == u.username {
			loggedin = true
		}
		c.ServePlain(200, []byte("success"))
	})
	PerformRequest(f, "POST", "/login")
	if !loggedin {
		t.Errorf("login did not occur")
	}
}

func TestLogout(t *testing.T) {
	loggedin := false
	f := testapp("test-logout", basemanager())
	f.POST("/logout", func(c *flotilla.Ctx) {
		l, _ := c.Call("loginmanager", c)
		m := l.(*Manager)
		u := tusers["one"]
		m.LoginUser(u, false, false)
		m.LogoutUser()
		if id := m.CurrentUser().GetId(); id == u.username {
			loggedin = true
		}
		c.ServePlain(200, []byte("success"))
	})
	PerformRequest(f, "POST", "/logout")
	if loggedin {
		t.Errorf("logout did not occur")
	}
}

func TestRefresh(t *testing.T) {
	refreshed := false
	f := testapp("test-refresh", basemanager())
	f.GET("/refresh", func(c *flotilla.Ctx) {
		l, _ := c.Call("loginmanager", c)
		m := l.(*Manager)
		u := tusers["one"]
		m.LoginUser(u, false, true)
		refreshed = c.Session.Get("_fresh").(bool)
		c.ServePlain(200, []byte("success"))
	})
	PerformRequest(f, "GET", "/refresh")
	if !refreshed {
		t.Errorf("refresh did not occur")
	}
}

func TestRefreshRequired(t *testing.T) {
	f := testapp("test-refresh", basemanager())
	f.GET("/refreshrequired", RefreshRequired(func(c *flotilla.Ctx) {}))
	r := PerformRequest(f, "GET", "/refreshrequired")
	if r.Code != http.StatusForbidden {
		t.Errorf("RefreshRequired: status code should be %v, was %d", http.StatusForbidden, r.Code)
	}
}

func TestRemembered(t *testing.T) {
	f := testapp("test-remember", basemanager())
	f.GET("/remembered", func(c *flotilla.Ctx) {
		l, _ := c.Call("loginmanager", c)
		m := l.(*Manager)
		u := tusers["one"]
		m.LoginUser(u, true, true)
		c.ServePlain(200, []byte("success"))
	})
	w := PerformRequest(f, "GET", "/remembered")
	if w.HeaderMap["Set-Cookie"][0][:14] != "remember_token" {
		t.Errorf("not remembered")
	}
}
