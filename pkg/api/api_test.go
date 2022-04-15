package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gavv/httpexpect/v2"
	"github.com/google/uuid"
	"github.com/jdpage/dnsacmed/pkg/db"
	"github.com/jdpage/dnsacmed/pkg/model"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// noAuth function to write ACMETxt model to context while not preforming any validation
func noAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		postData := model.ACMETxt{}
		uname := r.Header.Get("X-Api-User")
		passwd := r.Header.Get("X-Api-Key")

		dec := json.NewDecoder(r.Body)
		_ = dec.Decode(&postData)
		// Set user info to the decoded ACMETxt object
		postData.Username, _ = uuid.Parse(uname)
		postData.Password = passwd
		// Set the ACMETxt struct to context to pull in from update function
		ctx := r.Context()
		ctx = context.WithValue(ctx, ACMETxtKey, &postData)
		r = r.WithContext(ctx)
		next(w, r)
	}
}

func getExpect(t *testing.T, server *httptest.Server) *httpexpect.Expect {
	return httpexpect.WithConfig(httpexpect.Config{
		BaseURL:  server.URL,
		Reporter: httpexpect.NewAssertReporter(t),
		Printers: []httpexpect.Printer{
			httpexpect.NewCurlPrinter(t),
			httpexpect.NewDebugPrinter(t, true),
		},
	})
}

type routerOpts struct {
	noAuth    bool
	useHeader bool
}

type routerOpt func(opts routerOpts) routerOpts

func noAuth(opts routerOpts) routerOpts {
	opts.noAuth = true
	return opts
}

func useHeader(opts routerOpts) routerOpts {
	opts.useHeader = true
	return opts
}

func setupRouter(logger *zap.Logger, db db.Database, opts ...routerOpt) http.Handler {
	var options routerOpts
	for _, opt := range opts {
		options = opt(options)
	}

	config, dnsConfig := setupConfigs(options.useHeader)
	api := http.NewServeMux()
	api.Handle("/register", webRegisterHandler{&config, &dnsConfig, logger, db})
	api.Handle("/health", healthCheckHandler{logger, db})
	if options.noAuth {
		api.HandleFunc("/update", noAuthMiddleware(webUpdateHandler{logger, db}.ServeHTTP))
	} else {
		api.HandleFunc("/update", func(w http.ResponseWriter, r *http.Request) {
			authMiddleware{&config, logger, db}.ServeHTTP(w, r, webUpdateHandler{logger, db}.ServeHTTP)
		})
	}
	return api
}

func TestApiRegister(t *testing.T) {
	logger := zaptest.NewLogger(t)
	db := setupDB(t, logger)
	router := setupRouter(logger, db)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	e.POST("/register").Expect().
		Status(http.StatusCreated).
		JSON().Object().
		ContainsKey("fulldomain").
		ContainsKey("subdomain").
		ContainsKey("username").
		ContainsKey("password").
		NotContainsKey("error")

	allowfrom := map[string][]interface{}{
		"allowfrom": {
			"123.123.123.123/32",
			"2001:db8:a0b:12f0::1/32",
			"[::1]/64",
		},
	}

	response := e.POST("/register").
		WithJSON(allowfrom).
		Expect().
		Status(http.StatusCreated).
		JSON().Object().
		ContainsKey("fulldomain").
		ContainsKey("subdomain").
		ContainsKey("username").
		ContainsKey("password").
		ContainsKey("allowfrom").
		NotContainsKey("error")

	response.Value("allowfrom").Array().Elements("123.123.123.123/32", "2001:db8::/32", "::/64")
}

func TestApiRegisterBadAllowFrom(t *testing.T) {
	logger := zaptest.NewLogger(t)
	db := setupDB(t, logger)
	router := setupRouter(logger, db)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	invalidVals := []string{
		"invalid",
		"1.2.3.4/33",
		"1.2/24",
		"1.2.3.4",
		"12345:db8:a0b:12f0::1/32",
		"1234::123::123::1/32",
	}

	for _, v := range invalidVals {

		allowfrom := map[string][]interface{}{"allowfrom": {v}}

		response := e.POST("/register").
			WithJSON(allowfrom).
			Expect().
			Status(http.StatusBadRequest).
			JSON().Object().
			ContainsKey("error")

		response.Value("error").Equal("invalid_allowfrom_cidr")
	}
}

func TestApiRegisterMalformedJSON(t *testing.T) {
	logger := zaptest.NewLogger(t)
	db := setupDB(t, logger)
	router := setupRouter(logger, db)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)

	malPayloads := []string{
		"{\"allowfrom': '1.1.1.1/32'}",
		"\"allowfrom\": \"1.1.1.1/32\"",
		"{\"allowfrom\": \"[1.1.1.1/32]\"",
		"\"allowfrom\": \"1.1.1.1/32\"}",
		"{allowfrom: \"1.2.3.4\"}",
		"{allowfrom: [1.2.3.4]}",
		"whatever that's not a json payload",
	}
	for _, test := range malPayloads {
		e.POST("/register").
			WithBytes([]byte(test)).
			Expect().
			Status(http.StatusBadRequest).
			JSON().Object().
			ContainsKey("error").
			NotContainsKey("subdomain").
			NotContainsKey("username")
	}
}

func TestApiRegisterWithMockDB(t *testing.T) {
	logger := zaptest.NewLogger(t)
	db := setupDB(t, logger)
	router := setupRouter(logger, db)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	mdb, mock, _ := sqlmock.New()
	db.SetBackend(mdb)
	defer mdb.Close()
	mock.ExpectBegin()
	mock.ExpectPrepare("INSERT INTO records").WillReturnError(errors.New("error"))
	e.POST("/register").Expect().
		Status(http.StatusInternalServerError).
		JSON().Object().
		ContainsKey("error")
}

func TestApiUpdateWithInvalidSubdomain(t *testing.T) {
	validTxtData := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	updateJSON := map[string]interface{}{
		"subdomain": "",
		"txt":       ""}

	logger := zaptest.NewLogger(t)
	db := setupDB(t, logger)
	router := setupRouter(logger, db)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	newUser, err := db.Register(model.CIDRSlice{})
	if err != nil {
		t.Errorf("Could not create new user, got error [%v]", err)
	}
	// Invalid subdomain data
	updateJSON["subdomain"] = "example.com"
	updateJSON["txt"] = validTxtData
	e.POST("/update").
		WithJSON(updateJSON).
		WithHeader("X-Api-User", newUser.Username.String()).
		WithHeader("X-Api-Key", newUser.Password).
		Expect().
		Status(http.StatusUnauthorized).
		JSON().Object().
		ContainsKey("error").
		NotContainsKey("txt").
		ValueEqual("error", "forbidden")
}

func TestApiUpdateWithInvalidTxt(t *testing.T) {
	invalidTXTData := "idk m8 bbl lmao"

	updateJSON := map[string]interface{}{
		"subdomain": "",
		"txt":       ""}

	logger := zaptest.NewLogger(t)
	db := setupDB(t, logger)
	router := setupRouter(logger, db)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	newUser, err := db.Register(model.CIDRSlice{})
	if err != nil {
		t.Errorf("Could not create new user, got error [%v]", err)
	}
	updateJSON["subdomain"] = newUser.Subdomain
	// Invalid txt data
	updateJSON["txt"] = invalidTXTData
	e.POST("/update").
		WithJSON(updateJSON).
		WithHeader("X-Api-User", newUser.Username.String()).
		WithHeader("X-Api-Key", newUser.Password).
		Expect().
		Status(http.StatusBadRequest).
		JSON().Object().
		ContainsKey("error").
		NotContainsKey("txt").
		ValueEqual("error", "bad_txt")
}

func TestApiUpdateWithoutCredentials(t *testing.T) {
	logger := zaptest.NewLogger(t)
	db := setupDB(t, logger)
	router := setupRouter(logger, db)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	e.POST("/update").Expect().
		Status(http.StatusUnauthorized).
		JSON().Object().
		ContainsKey("error").
		NotContainsKey("txt")
}

func TestApiUpdateWithCredentials(t *testing.T) {
	validTxtData := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	updateJSON := map[string]interface{}{
		"subdomain": "",
		"txt":       ""}

	logger := zaptest.NewLogger(t)
	db := setupDB(t, logger)
	router := setupRouter(logger, db)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	newUser, err := db.Register(model.CIDRSlice{})
	if err != nil {
		t.Errorf("Could not create new user, got error [%v]", err)
	}
	// Valid data
	updateJSON["subdomain"] = newUser.Subdomain
	updateJSON["txt"] = validTxtData
	e.POST("/update").
		WithJSON(updateJSON).
		WithHeader("X-Api-User", newUser.Username.String()).
		WithHeader("X-Api-Key", newUser.Password).
		Expect().
		Status(http.StatusOK).
		JSON().Object().
		ContainsKey("txt").
		NotContainsKey("error").
		ValueEqual("txt", validTxtData)
}

func TestApiUpdateWithCredentialsMockDB(t *testing.T) {
	validTxtData := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	updateJSON := map[string]interface{}{
		"subdomain": "",
		"txt":       ""}

	// Valid data
	updateJSON["subdomain"] = "a097455b-52cc-4569-90c8-7a4b97c6eba8"
	updateJSON["txt"] = validTxtData

	logger := zaptest.NewLogger(t)
	db := setupDB(t, logger)
	router := setupRouter(logger, db, noAuth)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	mdb, mock, _ := sqlmock.New()
	db.SetBackend(mdb)
	defer mdb.Close()
	mock.ExpectBegin()
	mock.ExpectPrepare("UPDATE records").WillReturnError(errors.New("error"))
	e.POST("/update").
		WithJSON(updateJSON).
		Expect().
		Status(http.StatusInternalServerError).
		JSON().Object().
		ContainsKey("error")
}

func TestApiManyUpdateWithCredentials(t *testing.T) {
	validTxtData := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	logger := zaptest.NewLogger(t)
	db := setupDB(t, logger)
	router := setupRouter(logger, db, useHeader)
	server := httptest.NewServer(router)
	defer server.Close()
	// User without defined CIDR masks
	newUser, err := db.Register(model.CIDRSlice{})
	if err != nil {
		t.Errorf("Could not create new user, got error [%v]", err)
	}

	// User with defined allow from - CIDR masks, all invalid
	// (httpexpect doesn't provide a way to mock remote ip)
	cidrs, _ := model.ParseCIDRSlice([]string{"192.168.1.1/32", "invalid"})
	newUserWithCIDR, err := db.Register(cidrs)
	if err != nil {
		t.Errorf("Could not create new user with CIDR, got error [%v]", err)
	}

	// Another user with valid CIDR mask to match the httpexpect default
	cidrs, _ = model.ParseCIDRSlice([]string{"10.1.2.3/32", "invalid"})
	newUserWithValidCIDR, err := db.Register(cidrs)
	if err != nil {
		t.Errorf("Could not create new user with a valid CIDR, got error [%v]", err)
	}

	for i, test := range []struct {
		user      string
		pass      string
		subdomain string
		txt       interface{}
		status    int
	}{
		{"non-uuid-user", "tooshortpass", "non-uuid-subdomain", validTxtData, 401},
		{"a097455b-52cc-4569-90c8-7a4b97c6eba8", "tooshortpass", "bb97455b-52cc-4569-90c8-7a4b97c6eba8", validTxtData, 401},
		{"a097455b-52cc-4569-90c8-7a4b97c6eba8", "LongEnoughPassButNoUserExists___________", "bb97455b-52cc-4569-90c8-7a4b97c6eba8", validTxtData, 401},
		{newUser.Username.String(), newUser.Password, "a097455b-52cc-4569-90c8-7a4b97c6eba8", validTxtData, 401},
		{newUser.Username.String(), newUser.Password, newUser.Subdomain, "tooshortfortxt", 400},
		{newUser.Username.String(), newUser.Password, newUser.Subdomain, 1234567890, 400},
		{newUser.Username.String(), newUser.Password, newUser.Subdomain, validTxtData, 200},
		{newUserWithCIDR.Username.String(), newUserWithCIDR.Password, newUserWithCIDR.Subdomain, validTxtData, 401},
		{newUserWithValidCIDR.Username.String(), newUserWithValidCIDR.Password, newUserWithValidCIDR.Subdomain, validTxtData, 200},
		{newUser.Username.String(), "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", newUser.Subdomain, validTxtData, 401},
	} {
		t.Run(fmt.Sprintf("Test %d", i), func(t *testing.T) {
			e := getExpect(t, server)
			updateJSON := map[string]interface{}{
				"subdomain": test.subdomain,
				"txt":       test.txt}
			e.POST("/update").
				WithJSON(updateJSON).
				WithHeader("X-Api-User", test.user).
				WithHeader("X-Api-Key", test.pass).
				WithHeader("X-Forwarded-For", "10.1.2.3").
				Expect().
				Status(test.status)
		})
	}
}

func TestApiManyUpdateWithIpCheckHeaders(t *testing.T) {
	logger := zaptest.NewLogger(t)
	db := setupDB(t, logger)
	// Use header checks from default header (X-Forwarded-For)
	router := setupRouter(logger, db, useHeader)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	// User without defined CIDR masks
	newUser, err := db.Register(model.CIDRSlice{})
	if err != nil {
		t.Errorf("Could not create new user, got error [%v]", err)
	}

	cidrs, _ := model.ParseCIDRSlice([]string{"192.168.1.2/32", "invalid"})
	newUserWithCIDR, err := db.Register(cidrs)
	if err != nil {
		t.Errorf("Could not create new user with CIDR, got error [%v]", err)
	}

	cidrs, _ = model.ParseCIDRSlice([]string{"2002:c0a8::0/32"})
	newUserWithIP6CIDR, err := db.Register(cidrs)
	if err != nil {
		t.Errorf("Could not create a new user with IP6 CIDR, got error [%v]", err)
	}

	for _, test := range []struct {
		user        *model.ACMETxt
		headerValue string
		status      int
	}{
		{newUser, "whatever goes", 200},
		{newUser, "10.0.0.1, 1.2.3.4 ,3.4.5.6", 200},
		{newUserWithCIDR, "127.0.0.1", 401},
		{newUserWithCIDR, "10.0.0.1, 10.0.0.2, 192.168.1.3", 401},
		{newUserWithCIDR, "10.1.1.1 ,192.168.1.2, 8.8.8.8", 200},
		{newUserWithIP6CIDR, "2002:c0a8:b4dc:0d3::0", 200},
		{newUserWithIP6CIDR, "2002:c0a7:0ff::0", 401},
		{newUserWithIP6CIDR, "2002:c0a8:d3ad:b33f:c0ff:33b4:dc0d:3b4d", 200},
	} {
		updateJSON := map[string]interface{}{
			"subdomain": test.user.Subdomain,
			"txt":       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
		e.POST("/update").
			WithJSON(updateJSON).
			WithHeader("X-Api-User", test.user.Username.String()).
			WithHeader("X-Api-Key", test.user.Password).
			WithHeader("X-Forwarded-For", test.headerValue).
			Expect().
			Status(test.status)
	}
}

func TestApiHealthCheck(t *testing.T) {
	logger := zaptest.NewLogger(t)
	db := setupDB(t, logger)
	router := setupRouter(logger, db)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	e.GET("/health").Expect().Status(http.StatusOK)
}
