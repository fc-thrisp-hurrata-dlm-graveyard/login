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

func basemanager() *LoginManager {
	l := New()
	l.UserLoader = InMemoryUserLoader
	return l
}

func extmanager() *LoginManager {
	b := basemanager()
	return b
}

func testhandler(c *flotilla.Ctx) {
	//passed := true
	//l, _ := c.Call("loginmanager", c)
	//m := l.(*LoginManager)
	//uid := m.currentuserid()
	//cu := m.Currentuser()
	//fmt.Printf("%+v %+v\n", uid, cu)
}

func testapp(name string, m *LoginManager) *flotilla.App {
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
		if _, ok := l.(*LoginManager); ok {
			exists = true
		}
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
		t.Errorf("Status code should be %v, was %d", http.StatusUnauthorized, r.Code)
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

func TestSimpleLogin(t *testing.T) {
	loggedin := false
	f := testapp("test-simplelogin", basemanager())
	f.GET("/simplelogin", func(c *flotilla.Ctx) {
		l, _ := c.Call("loginmanager", c)
		m := l.(*LoginManager)
		u := tusers["one"]
		m.Loginuser(u, false)
		if id := m.Currentuser().GetId(); id == u.username {
			loggedin = true
		}
	})
	PerformRequest(f, "GET", "/simplelogin")
	if !loggedin {
		t.Errorf("simple login did not occur")
	}
}
