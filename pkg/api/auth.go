package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/jdpage/dnsacmed/pkg/db"
	"github.com/jdpage/dnsacmed/pkg/model"
	"go.uber.org/zap"
)

type key int

// ACMETxtKey is a context key for ACMETxt struct
const ACMETxtKey key = 0

// Auth middleware for update request
type authMiddleware struct {
	config *Config
	logger *zap.Logger
	db     db.Database
}

func (m authMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	postData := model.ACMETxt{}
	userOK := false
	user, err := m.getUserFromRequest(r)
	if err == nil {
		if m.updateAllowedFromIP(r, user) {
			dec := json.NewDecoder(r.Body)
			err = dec.Decode(&postData)
			if err != nil {
				m.logger.Error("JSON decode error", zap.Error(err))
			}
			if user.Subdomain == postData.Subdomain {
				userOK = true
			} else {
				m.logger.Error("Subdomain mismatch", zap.String("error", "subdomain_mismatch"), zap.String("name", postData.Subdomain), zap.String("expected", user.Subdomain))
			}
		} else {
			m.logger.Error("Update not allowed from IP", zap.String("error", "ip_unauthorized"))
		}
	} else {
		m.logger.Error("Error while trying to get user", zap.Error(err))
	}
	if userOK {
		// Set user info to the decoded ACMETxt object
		postData.Username = user.Username
		postData.Password = user.Password
		// Set the ACMETxt struct to context to pull in from update function
		ctx := context.WithValue(r.Context(), ACMETxtKey, &postData)
		next(w, r.WithContext(ctx))
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(jsonError("forbidden"))
	}
}

func (m authMiddleware) getUserFromRequest(r *http.Request) (*model.ACMETxt, error) {
	uname := r.Header.Get("X-Api-User")
	passwd := r.Header.Get("X-Api-Key")
	username, err := getValidUsername(uname)
	if err != nil {
		return nil, fmt.Errorf("Invalid username: %s: %s", uname, err.Error())
	}
	if validKey(passwd) {
		dbuser, err := m.db.GetByUsername(username)
		if err != nil {
			m.logger.Error("While trying to get user", zap.Error(err))
			// To protect against timed side channel (never gonna give you up)
			db.CorrectPassword(passwd, "$2a$10$8JEFVNYYhLoBysjAxe2yBuXrkDojBQBkVpXEQgyQyjn43SvJ4vL36")

			return nil, fmt.Errorf("Invalid username: %s", uname)
		}
		if db.CorrectPassword(passwd, dbuser.Password) {
			return dbuser, nil
		}
		return nil, fmt.Errorf("Invalid password for user %s", uname)
	}
	return nil, fmt.Errorf("Invalid key for user %s", uname)
}

func (m authMiddleware) updateAllowedFromIP(r *http.Request, user *model.ACMETxt) bool {
	if m.config.UseHeader {
		ips := getIPListFromHeader(r.Header.Get(m.config.HeaderName))
		return user.IsAllowedFromList(m.logger, ips)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		m.logger.Error("While parsing remote address", zap.Error(err), zap.String("remoteaddr", r.RemoteAddr))
		host = ""
	}
	return user.IsAllowedFrom(m.logger, host)
}

func getIPListFromHeader(header string) []string {
	iplist := []string{}
	for _, v := range strings.Split(header, ",") {
		if len(v) > 0 {
			// Ignore empty values
			iplist = append(iplist, strings.TrimSpace(v))
		}
	}
	return iplist
}
