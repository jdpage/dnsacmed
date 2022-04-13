package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"go.uber.org/zap"
)

// RegResponse is a struct for registration response JSON
type RegResponse struct {
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	Fulldomain string   `json:"fulldomain"`
	Subdomain  string   `json:"subdomain"`
	Allowfrom  []string `json:"allowfrom"`
}

type webRegisterHandler struct {
	config *Config
	logger *zap.Logger
	db     database
}

func (h webRegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var regStatus int
	var reg []byte
	var err error
	aTXT := ACMETxt{}
	bdata, _ := ioutil.ReadAll(r.Body)
	if len(bdata) > 0 {
		err = json.Unmarshal(bdata, &aTXT)
		if err != nil {
			regStatus = http.StatusBadRequest
			reg = jsonError("malformed_json_payload")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(regStatus)
			_, _ = w.Write(reg)
			return
		}
	}

	// Fail with malformed CIDR mask in allowfrom
	err = aTXT.AllowFrom.isValid()
	if err != nil {
		regStatus = http.StatusBadRequest
		reg = jsonError("invalid_allowfrom_cidr")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(regStatus)
		_, _ = w.Write(reg)
		return
	}

	// Create new user
	nu, err := h.db.Register(aTXT.AllowFrom)
	if err != nil {
		errstr := fmt.Sprintf("%v", err)
		reg = jsonError(errstr)
		regStatus = http.StatusInternalServerError
		h.logger.Debug("Error in registration", zap.Error(err))
	} else {
		h.logger.Debug("Created new user", zap.Any("user", nu.Username))
		regStruct := RegResponse{nu.Username.String(), nu.Password, nu.Subdomain + "." + h.config.DNS.Domain, nu.Subdomain, nu.AllowFrom.ValidEntries()}
		regStatus = http.StatusCreated
		reg, err = json.Marshal(regStruct)
		if err != nil {
			regStatus = http.StatusInternalServerError
			reg = jsonError("json_error")
			h.logger.Debug("Could not marshal JSON", zap.String("error", "json"))
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(regStatus)
	_, _ = w.Write(reg)
}

type webUpdateHandler struct {
	logger *zap.Logger
	db     database
}

func (h webUpdateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var updStatus int
	var upd []byte
	// Get user
	a, ok := r.Context().Value(ACMETxtKey).(ACMETxt)
	if !ok {
		h.logger.Error("Context error", zap.String("error", "context"))
	}
	// NOTE: An invalid subdomain should not happen - the auth handler should
	// reject POSTs with an invalid subdomain before this handler. Reject any
	// invalid subdomains anyway as a matter of caution.
	if !validSubdomain(a.Subdomain) {
		h.logger.Debug("Bad update data", zap.String("error", "subdomain"), zap.String("subdomain", a.Subdomain), zap.String("txt", a.Value))
		updStatus = http.StatusBadRequest
		upd = jsonError("bad_subdomain")
	} else if !validTXT(a.Value) {
		h.logger.Debug("Bad update data", zap.String("error", "txt"), zap.String("subdomain", a.Subdomain), zap.String("txt", a.Value))
		updStatus = http.StatusBadRequest
		upd = jsonError("bad_txt")
	} else if validSubdomain(a.Subdomain) && validTXT(a.Value) {
		err := h.db.Update(a.ACMETxtPost)
		if err != nil {
			h.logger.Error("Error while trying to update record", zap.Error(err))
			updStatus = http.StatusInternalServerError
			upd = jsonError("db_error")
		} else {
			h.logger.Debug("TXT updated", zap.String("subdomain", a.Subdomain), zap.String("txt", a.Value))
			updStatus = http.StatusOK
			upd = []byte("{\"txt\": \"" + a.Value + "\"}")
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(updStatus)
	_, _ = w.Write(upd)
}

// Endpoint used to check the readiness and/or liveness (health) of the server.
func healthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusOK)
}
