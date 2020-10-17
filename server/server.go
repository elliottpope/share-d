package server

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/elliottpope/share-d/backends"
	"github.com/elliottpope/share-d/secrets"
	"github.com/julienschmidt/httprouter"
)

// Server ... component to receive and return secrets over HTTP
type Server struct {
	Backend     backends.Backend
	Router      *httprouter.Router
	ErrorLogger *log.Logger
}

// HTTPError ... encapsulates details of an HTTP Error to be raised and displayed to the client
type HTTPError struct {
	HTTPCode int    `json:"-"`
	Message  string `json:"error-message"`
	Code     string `json:"error-code,omitempty"`
	Cause    error  `json:"-"`
}

// Start ... starts the server and registers the necessary HTTP endpoints
func (server *Server) Start() {
	if server.ErrorLogger == nil {
		server.ErrorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	}
	server.registerEndpoints()
	log.Fatal(http.ListenAndServe(":8080", server.Router))
}

func (server *Server) registerEndpoints() *httprouter.Router {
	server.Router = httprouter.New()

	server.Router.HandlerFunc("LIST", "/secrets", server.listSecrets)
	server.Router.HandlerFunc("GET", "/secrets/:id", server.getSecret)
	server.Router.HandlerFunc("POST", "/secrets", server.addSecret)
	server.Router.HandlerFunc("PUT", "/secrets/:id", server.replaceSecret)
	server.Router.HandlerFunc("PATCH", "/secrets/:id", server.updateSecret)
	server.Router.HandlerFunc("DELETE", "/secrets/:id", server.deleteSecret)

	return server.Router
}

func (server *Server) listSecrets(w http.ResponseWriter, r *http.Request) {

	metadata, err := server.Backend.List()

	if err != nil {
		server.raiseHTTPError(w, &HTTPError{
			Message:  "There was an error while finding secrets",
			Cause:    err,
			HTTPCode: http.StatusInternalServerError,
		})
		return
	}

	output, err := json.Marshal(metadata)

	if err != nil {
		log.Print(err)
		server.raiseHTTPError(w, &HTTPError{
			Message:  "There was an error while finding secrets",
			Cause:    err,
			HTTPCode: http.StatusInternalServerError,
		})
		return
	}

	w.Write(output)
}

func (server *Server) getSecret(w http.ResponseWriter, r *http.Request) {
	params := httprouter.ParamsFromContext(r.Context())
	id := params.ByName("id")

	secret, err := server.Backend.Read(id)

	if err != nil {
		server.raiseHTTPError(w, &HTTPError{
			Message:  "Share-d was unable to read the secret with ID: " + id,
			Cause:    err,
			HTTPCode: http.StatusInternalServerError,
		})
		return
	}

	output, err := json.Marshal(secret)

	if err != nil {
		server.raiseHTTPError(w, &HTTPError{
			Message:  "There was an error while reading the secret with ID: " + id,
			Cause:    err,
			HTTPCode: http.StatusInternalServerError,
		})
		return
	}

	w.Write(output)

}

func (server *Server) addSecret(w http.ResponseWriter, r *http.Request) {

	request := r.Body
	requestBody, err := ioutil.ReadAll(request)

	if err != nil {
		server.raiseHTTPError(w, &HTTPError{
			HTTPCode: http.StatusBadRequest,
			Message:  "Unable to read the provided secret",
			Cause:    err,
		})
		return
	}

	var secret secrets.Secret

	json.Unmarshal(requestBody, &secret)

	if secret.EncryptedValue == "" {
		server.raiseHTTPError(w, &HTTPError{
			HTTPCode: http.StatusNotAcceptable,
			Message:  "Encrypted Value must be provided",
		})
		return
	}

	metadata, err := server.Backend.Save(secret)

	if err, ok := err.(*backends.SecretAlreadyExistsError); ok {
		server.raiseHTTPError(w, &HTTPError{
			HTTPCode: http.StatusConflict,
			Message:  "Secret with the given ID already exists",
		})
		return
	} else if err != nil {
		server.raiseHTTPError(w, &HTTPError{
			HTTPCode: http.StatusInternalServerError,
			Message:  "Share-d was unable to store the provided secret",
			Cause:    err,
		})
		return
	}

	output, _ := json.Marshal(&metadata)
	w.Write(output)
}

func (server *Server) replaceSecret(w http.ResponseWriter, r *http.Request) {

	params := httprouter.ParamsFromContext(r.Context())
	id := params.ByName("id")

	request := r.Body
	requestBody, err := ioutil.ReadAll(request)

	if err != nil {
		server.raiseHTTPError(w, &HTTPError{
			HTTPCode: http.StatusBadRequest,
			Message:  "Unable to read the provided secret",
			Cause:    err,
		})
		return
	}

	var secret secrets.Secret

	json.Unmarshal(requestBody, &secret)

	if secret.EncryptedValue == "" {
		server.raiseHTTPError(w, &HTTPError{
			HTTPCode: http.StatusNotAcceptable,
			Message:  "Encrypted Value must be provided",
		})
		return
	}

	if updatedSecret, err := server.Backend.Replace(id, secret); err == nil {
		// can ignore error here since we just unmarshalled it from JSON
		output, _ := json.Marshal(&updatedSecret)
		w.Write(output)
		return
	} else if _, ok := err.(*backends.SecretDoesNotExistError); ok {
		server.raiseHTTPError(w, &HTTPError{
			HTTPCode: http.StatusNotFound,
			Message:  "Secret with the given ID does not exist",
		})
		return
	}

	server.raiseHTTPError(w, &HTTPError{
		HTTPCode: http.StatusInternalServerError,
		Message:  "Share-d was unable to store the provided secret",
		Cause:    err,
	})
}

func (server *Server) updateSecret(w http.ResponseWriter, r *http.Request) {
	params := httprouter.ParamsFromContext(r.Context())
	id := params.ByName("id")

	request := r.Body
	requestBody, err := ioutil.ReadAll(request)

	if err != nil {
		server.raiseHTTPError(w, &HTTPError{
			HTTPCode: http.StatusBadRequest,
			Message:  "Unable to read the provided secret",
			Cause:    err,
		})
		return
	}

	var secret secrets.Secret

	json.Unmarshal(requestBody, &secret)

	if secret, err := server.Backend.Update(id, secret); err == nil {

		// can ignore error here since we just unmarshalled it from JSON
		output, _ := json.Marshal(&secret)
		w.Write(output)
	} else if _, ok := err.(*backends.SecretDoesNotExistError); ok {
		server.raiseHTTPError(w, &HTTPError{
			HTTPCode: http.StatusNotFound,
			Message:  "Secret with the given ID does not exist",
		})
		return
	}

	server.raiseHTTPError(w, &HTTPError{
		HTTPCode: http.StatusInternalServerError,
		Message:  "An unexpected error occured",
	})
}

func (server *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	params := httprouter.ParamsFromContext(r.Context())
	id := params.ByName("id")

	if err := server.Backend.Delete(id); err == nil {
		w.WriteHeader(http.StatusAccepted)
	} else if _, ok := err.(*backends.SecretDoesNotExistError); ok {
		server.raiseHTTPError(w, &HTTPError{
			HTTPCode: http.StatusNotFound,
			Message:  err.Error(),
		})
		return
	}

	server.raiseHTTPError(w, &HTTPError{
		HTTPCode: http.StatusInternalServerError,
		Message:  "An unexpected error occured.",
	})
}

func (server *Server) raiseHTTPError(w http.ResponseWriter, err *HTTPError) {
	server.ErrorLogger.Println(err.Cause)

	output, outputErr := json.Marshal(err)
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if outputErr != nil {
		server.ErrorLogger.Println(outputErr)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(w, "There was an unexpected error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(err.HTTPCode)
	w.Write(output)
}
