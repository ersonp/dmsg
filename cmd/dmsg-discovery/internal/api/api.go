package api

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/gorilla/handlers"
	"github.com/sirupsen/logrus"
	"github.com/skycoin/skycoin/src/util/logging"

	"github.com/skycoin/dmsg/cipher"
	"github.com/skycoin/dmsg/cmd/dmsg-discovery/internal/store"
	"github.com/skycoin/dmsg/disc"
	"github.com/skycoin/dmsg/httputil"
)

var log = logging.MustGetLogger("dmsg-discovery")

const maxGetAvailableServersResult = 512

// API represents the api of the dmsg-discovery service`
type API struct {
	log      logrus.FieldLogger
	db       store.Storer
	testMode bool
	router   http.Handler
}

// New returns a new API object, which can be started as a server
func New(log logrus.FieldLogger, db store.Storer, testMode bool) *API {
	if log != nil {
		log = logging.MustGetLogger("dmsg_disc")
	}
	if db == nil {
		panic("cannot create new api without a store.Storer")
	}

	r := chi.NewRouter()
	api := &API{
		log:      log,
		db:       db,
		testMode: testMode,
		router:   r,
	}

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/dmsg-discovery/entry/{pk}", api.getEntry())
	r.Post("/dmsg-discovery/entry/", api.setEntry())
	r.Post("/dmsg-discovery/entry/{pk}", api.setEntry())
	r.Get("/dmsg-discovery/available_servers", api.getAvailableServers())
	r.Get("/dmsg-discovery/health", api.health())

	return api
}

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := a.log.WithField("_module", "dmsgdisc_api")

	w.Header().Set("Content-Type", "application/json")
	handlers.CustomLoggingHandler(log.Writer(), a.router, httputil.WriteLog).
		ServeHTTP(w, r)
}

// getEntry returns the entry associated with the given public key
// URI: /dmsg-discovery/entry/:pk
// Method: GET
func (a *API) getEntry() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		staticPK := cipher.PubKey{}
		if err := staticPK.UnmarshalText([]byte(chi.URLParam(r, "pk"))); err != nil {
			a.handleError(w, disc.ErrBadInput)
			return
		}

		entry, err := a.db.Entry(r.Context(), staticPK)

		// If we make sure that every error is handled then we can
		// remove the if and make the entry return the switch default
		if err != nil {
			a.handleError(w, err)
			return
		}

		a.writeJSON(w, http.StatusOK, entry)
	}
}

// setEntry adds a new entry associated with the given public key
// or updates a previous one if signed by the same instance that
// created the previous one
// URI: /dmsg-discovery/entry/
// Method: POST
// Args:
//	json serialized entry object
func (a *API) setEntry() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := r.Body.Close(); err != nil {
				log.WithError(err).Warn("Failed to decode HTTP response body")
			}
		}()

		entry := new(disc.Entry)
		if err := json.NewDecoder(r.Body).Decode(entry); err != nil {
			a.handleError(w, disc.ErrUnexpected)
			return
		}

		if entry.Server != nil && !a.testMode {
			if ok, err := isLoopbackAddr(entry.Server.Address); ok {
				if err != nil && a.log != nil {
					a.log.Warningf("failed to parse hostname and port: %s", err)
				}

				a.handleError(w, disc.ErrValidationServerAddress)
				return
			}
		}

		if err := entry.Validate(); err != nil {
			a.handleError(w, err)
			return
		}

		if err := entry.VerifySignature(); err != nil {
			a.handleError(w, disc.ErrUnauthorized)
			return
		}

		// Recover previous entry. If key not found we insert with sequence 0
		// If there was a previous entry we check the new one is a valid iteration
		oldEntry, err := a.db.Entry(r.Context(), entry.Static)
		if err == disc.ErrKeyNotFound {
			setErr := a.db.SetEntry(r.Context(), entry)
			if setErr != nil {
				a.handleError(w, setErr)
				return
			}

			a.writeJSON(w, http.StatusOK, disc.MsgEntrySet)

			return
		} else if err != nil {
			a.handleError(w, err)
			return
		}

		if err := oldEntry.ValidateIteration(entry); err != nil {
			a.handleError(w, err)
			return
		}

		if err := a.db.SetEntry(r.Context(), entry); err != nil {
			a.handleError(w, err)
			return
		}

		a.writeJSON(w, http.StatusOK, disc.MsgEntryUpdated)
	}
}

// getAvailableServers returns all available server entries as an array of json codified entry objects
// URI: /dmsg-discovery/available_servers
// Method: GET
func (a *API) getAvailableServers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := a.db.AvailableServers(r.Context(), maxGetAvailableServersResult)
		if err != nil {
			a.handleError(w, err)
			return
		}

		if len(entries) == 0 {
			a.writeJSON(w, http.StatusNotFound, disc.HTTPMessage{
				Code:    http.StatusNotFound,
				Message: disc.ErrNoAvailableServers.Error(),
			})

			return
		}

		a.writeJSON(w, http.StatusOK, entries)
	}
}

// health returns status of dmsg discovery
// URI: /dmsg-discovery/health
// Method: GET
func (a *API) health() http.HandlerFunc {
	const expBase = "health"
	return httputil.MakeHealthHandler(a.log, expBase, nil)
}

// isLoopbackAddr checks if string is loopback interface
func isLoopbackAddr(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, err
	}

	if host == "" {
		return true, nil
	}

	return net.ParseIP(host).IsLoopback(), nil
}

// writeJSON writes a json object on a http.ResponseWriter with the given code.
func (a *API) writeJSON(w http.ResponseWriter, code int, object interface{}) {
	jsonObject, err := json.Marshal(object)
	if err != nil {
		a.log.Warnf("Failed to encode json response: %s", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	_, err = w.Write(jsonObject)
	if err != nil {
		a.log.Warnf("Failed to write response: %s", err)
	}
}
