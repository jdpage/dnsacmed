package db

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"flag"
	"testing"

	"github.com/erikstmartin/go-testdb"
	"github.com/jdpage/dnsacmed/pkg/model"
	"go.uber.org/zap/zaptest"
)

var (
	postgres = flag.Bool("postgres", false, "run integration tests against PostgreSQL")
)

type testResult struct {
	lastID       int64
	affectedRows int64
}

func (r testResult) LastInsertId() (int64, error) {
	return r.lastID, nil
}

func (r testResult) RowsAffected() (int64, error) {
	return r.affectedRows, nil
}

func setupDB(t *testing.T) Database {
	logger := zaptest.NewLogger(t)
	var db Database
	if *postgres {
		var err error
		db, err = NewACMEDB(logger, Config{"postgres", "postgres://acmedns:acmedns@localhost/acmedns"})
		if err != nil {
			t.Fatal("PostgreSQL integration tests expect database \"acmedns\" running in localhost, with username and password set to \"acmedns\"")
		}
	} else {
		db, _ = NewACMEDB(logger, Config{"sqlite3", ":memory:"})
	}
	return db
}

func TestDBInit(t *testing.T) {
	logger := zaptest.NewLogger(t)

	if _, err := NewACMEDB(logger, Config{"notarealengine", "connectionstring"}); err == nil {
		t.Errorf("Was expecting error, didn't get one.")
	}

	testdb.SetExecWithArgsFunc(func(query string, args []driver.Value) (result driver.Result, err error) {
		return testResult{1, 0}, errors.New("Prepared query error")
	})
	defer testdb.Reset()

	_, err := NewACMEDB(logger, Config{"testdb", ""})
	if err == nil {
		t.Errorf("Was expecting DB initiation error but got none")
	}
}

func TestRegisterNoCIDR(t *testing.T) {
	db := setupDB(t)

	// Register tests
	_, err := db.Register(model.CIDRSlice{})
	if err != nil {
		t.Errorf("Registration failed, got error [%v]", err)
	}
}

func TestRegisterMany(t *testing.T) {
	for _, test := range []struct {
		name   string
		input  []string
		output []string
	}{
		{"all good", []string{"127.0.0.1/8", "8.8.8.8/32", "1.0.0.1/1"}, []string{"127.0.0.1/8", "8.8.8.8/32", "1.0.0.1/1"}},
		{"all invalid", []string{"1.1.1./32", "1922.168.42.42/8", "1.1.1.1/33", "1.2.3.4/"}, []string{}},
		{"some invalid", []string{"7.6.5.4/32", "invalid", "1.0.0.1/2"}, []string{"7.6.5.4/32", "1.0.0.1/2"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := setupDB(t)
			nets, _ := model.ParseCIDRSlice(test.input)
			user, err := db.Register(nets)
			if err != nil {
				t.Errorf("Got error from register method: [%v]", err)
			}
			res, err := db.GetByUsername(user.Username)
			if err != nil {
				t.Errorf("Got error when fetching username: [%v]", err)
			}
			if len(user.AllowFrom) != len(test.output) {
				t.Errorf("Expected to receive struct with [%d] entries in AllowFrom, but got [%d] records", len(test.output), len(user.AllowFrom))
			}
			if len(res.AllowFrom) != len(test.output) {
				t.Errorf("Expected to receive struct with [%d] entries in AllowFrom, but got [%d] records", len(test.output), len(res.AllowFrom))
			}
		})
	}
}

func TestGetByUsername(t *testing.T) {
	db := setupDB(t)

	// Create  reg to refer to
	reg, err := db.Register(model.CIDRSlice{})
	if err != nil {
		t.Errorf("Registration failed, got error [%v]", err)
	}

	regUser, err := db.GetByUsername(reg.Username)
	if err != nil {
		t.Errorf("Could not get test user, got error [%v]", err)
	}

	if reg.Username != regUser.Username {
		t.Errorf("GetByUsername username [%q] did not match the original [%q]", regUser.Username, reg.Username)
	}

	if reg.Subdomain != regUser.Subdomain {
		t.Errorf("GetByUsername subdomain [%q] did not match the original [%q]", regUser.Subdomain, reg.Subdomain)
	}

	// regUser password already is a bcrypt hash
	if !CorrectPassword(reg.Password, regUser.Password) {
		t.Errorf("The password [%s] does not match the hash [%s]", reg.Password, regUser.Password)
	}
}

func TestPrepareErrors(t *testing.T) {
	db := setupDB(t)

	reg, _ := db.Register(model.CIDRSlice{})
	tdb, err := sql.Open("testdb", "")
	if err != nil {
		t.Errorf("Got error: %v", err)
	}
	oldDb := db.GetBackend()
	db.SetBackend(tdb)
	defer db.SetBackend(oldDb)
	defer testdb.Reset()

	_, err = db.GetByUsername(reg.Username)
	if err == nil {
		t.Errorf("Expected error, but didn't get one")
	}

	_, err = db.GetTXTForDomain(reg.Subdomain)
	if err == nil {
		t.Errorf("Expected error, but didn't get one")
	}
}

func TestQueryExecErrors(t *testing.T) {
	db := setupDB(t)

	reg, _ := db.Register(model.CIDRSlice{})
	testdb.SetExecWithArgsFunc(func(query string, args []driver.Value) (result driver.Result, err error) {
		return testResult{1, 0}, errors.New("Prepared query error")
	})

	testdb.SetQueryWithArgsFunc(func(query string, args []driver.Value) (result driver.Rows, err error) {
		columns := []string{"Username", "Password", "Subdomain", "Value", "LastActive"}
		return testdb.RowsFromSlice(columns, [][]driver.Value{}), errors.New("Prepared query error")
	})

	defer testdb.Reset()

	tdb, err := sql.Open("testdb", "")
	if err != nil {
		t.Errorf("Got error: %v", err)
	}
	oldDb := db.GetBackend()

	db.SetBackend(tdb)
	defer db.SetBackend(oldDb)

	_, err = db.GetByUsername(reg.Username)
	if err == nil {
		t.Errorf("Expected error from exec, but got none")
	}

	_, err = db.GetTXTForDomain(reg.Subdomain)
	if err == nil {
		t.Errorf("Expected error from exec in GetByDomain, but got none")
	}

	_, err = db.Register(model.CIDRSlice{})
	if err == nil {
		t.Errorf("Expected error from exec in Register, but got none")
	}
	reg.Value = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	err = db.Update(&reg.ACMETxtPost)
	if err == nil {
		t.Errorf("Expected error from exec in Update, but got none")
	}

}

func TestQueryScanErrors(t *testing.T) {
	db := setupDB(t)
	reg, _ := db.Register(model.CIDRSlice{})

	testdb.SetExecWithArgsFunc(func(query string, args []driver.Value) (result driver.Result, err error) {
		return testResult{1, 0}, errors.New("Prepared query error")
	})

	testdb.SetQueryWithArgsFunc(func(query string, args []driver.Value) (result driver.Rows, err error) {
		columns := []string{"Only one"}
		resultrows := "this value"
		return testdb.RowsFromCSVString(columns, resultrows), nil
	})

	defer testdb.Reset()
	tdb, err := sql.Open("testdb", "")
	if err != nil {
		t.Errorf("Got error: %v", err)
	}
	oldDb := db.GetBackend()

	db.SetBackend(tdb)
	defer db.SetBackend(oldDb)

	_, err = db.GetByUsername(reg.Username)
	if err == nil {
		t.Errorf("Expected error from scan in, but got none")
	}
}

func TestBadDBValues(t *testing.T) {
	db := setupDB(t)
	reg, _ := db.Register(model.CIDRSlice{})

	testdb.SetQueryWithArgsFunc(func(query string, args []driver.Value) (result driver.Rows, err error) {
		columns := []string{"Username", "Password", "Subdomain", "Value", "LastActive"}
		resultrows := "invalid,invalid,invalid,invalid,"
		return testdb.RowsFromCSVString(columns, resultrows), nil
	})

	defer testdb.Reset()
	tdb, err := sql.Open("testdb", "")
	if err != nil {
		t.Errorf("Got error: %v", err)
	}
	oldDb := db.GetBackend()

	db.SetBackend(tdb)
	defer db.SetBackend(oldDb)

	_, err = db.GetByUsername(reg.Username)
	if err == nil {
		t.Errorf("Expected error from scan in, but got none")
	}

	_, err = db.GetTXTForDomain(reg.Subdomain)
	if err == nil {
		t.Errorf("Expected error from scan in GetByDomain, but got none")
	}
}

func TestGetTXTForDomain(t *testing.T) {
	db := setupDB(t)

	// Create  reg to refer to
	reg, err := db.Register(model.CIDRSlice{})
	if err != nil {
		t.Errorf("Registration failed, got error [%v]", err)
	}

	txtval1 := "___validation_token_received_from_the_ca___"
	txtval2 := "___validation_token_received_YEAH_the_ca___"

	reg.Value = txtval1
	_ = db.Update(&reg.ACMETxtPost)

	reg.Value = txtval2
	_ = db.Update(&reg.ACMETxtPost)

	regDomainSlice, err := db.GetTXTForDomain(reg.Subdomain)
	if err != nil {
		t.Errorf("Could not get test user, got error [%v]", err)
	}
	if len(regDomainSlice) == 0 {
		t.Errorf("No rows returned for GetTXTForDomain [%s]", reg.Subdomain)
	}

	var val1found = false
	var val2found = false
	for _, v := range regDomainSlice {
		if v == txtval1 {
			val1found = true
		}
		if v == txtval2 {
			val2found = true
		}
	}
	if !val1found {
		t.Errorf("No TXT value found for val1")
	}
	if !val2found {
		t.Errorf("No TXT value found for val2")
	}

	// Not found
	regNotfound, _ := db.GetTXTForDomain("does-not-exist")
	if len(regNotfound) > 0 {
		t.Errorf("No records should be returned.")
	}
}

func TestUpdate(t *testing.T) {
	db := setupDB(t)

	// Create  reg to refer to
	reg, err := db.Register(model.CIDRSlice{})
	if err != nil {
		t.Errorf("Registration failed, got error [%v]", err)
	}

	regUser, err := db.GetByUsername(reg.Username)
	if err != nil {
		t.Errorf("Could not get test user, got error [%v]", err)
	}

	// Set new values (only TXT should be updated) (matches by username and subdomain)

	validTXT := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	regUser.Password = "nevergonnagiveyouup"
	regUser.Value = validTXT

	err = db.Update(&regUser.ACMETxtPost)
	if err != nil {
		t.Errorf("DB Update failed, got error: [%v]", err)
	}
}

func TestCorrectPassword(t *testing.T) {
	for i, test := range []struct {
		pw     string
		hash   string
		output bool
	}{
		{"PUrNTjU24JYNEOCeS2JcjaJGv1sinT80oV9--dpX",
			"$2a$10$ldVoGU5yrdlbPzuPUbUfleVovGjaRelP9tql0IltVUJk778gf.2tu",
			true},
		{"PUrNTjU24JYNEOCeS2JcjaJGv1sinT80oV9--dpX",
			"$2a$10$ldVoGU5yrdlbPzuPUbUfleVovGjaRelP9tql0IltVUJk778gf.2t",
			false},
		{"PUrNTjU24JYNEOCeS2JcjaJGv1sinT80oV9--dp",
			"$2a$10$ldVoGU5yrdlbPzuPUbUfleVovGjaRelP9tql0IltVUJk778gf.2tu",
			false},
		{"", "", false},
	} {
		ret := CorrectPassword(test.pw, test.hash)
		if ret != test.output {
			t.Errorf("Test %d: Expected return value %t, but got %t", i, test.output, ret)
		}
	}
}
