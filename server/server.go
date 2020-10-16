package server

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/elliottpope/share-d/backends"
	"github.com/elliottpope/share-d/secrets"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
)

// Server ... component to receive and return secrets over HTTP
type Server struct {
	Backend backends.Backend
	Router  *httprouter.Router
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
	server.registerEndpoints()
	log.Fatal(http.ListenAndServe(":8080", server.Router))
}

func (server *Server) registerEndpoints() *httprouter.Router {
	server.Router = httprouter.New()

	server.Router.HandlerFunc("LIST", "/secrets", server.listSecrets)
	server.Router.HandlerFunc("GET", "/secrets/:id", getSecret)
	server.Router.HandlerFunc("POST", "/secrets", addSecret)
	server.Router.HandlerFunc("PUT", "/secrets/:id", replaceSecret)
	server.Router.HandlerFunc("PATCH", "/secrets/:id", updateSecret)
	server.Router.HandlerFunc("DELETE", "/secrets/:id", deleteSecret)

	return server.Router
}

func (server *Server) listSecrets(w http.ResponseWriter, r *http.Request) {

	metadata, err := server.Backend.List()

	if err != nil {
		raiseHTTPError(w, &HTTPError{
			Message:  "There was an error while finding secrets",
			Cause:    err,
			HTTPCode: 500,
		})
		return
	}

	output, err := json.Marshal(metadata)

	if err != nil {
		log.Print(err)
		raiseHTTPError(w, &HTTPError{
			Message:  "There was an error while finding secrets",
			Cause:    err,
			HTTPCode: 500,
		})
		return
	}

	w.Write(output)
}

func (server *Server) getSecret(w http.ResponseWriter, r *http.Request) {
	params := httprouter.ParamsFromContext(r.Context())
	id := params.ByName("id")

	file, err := server.Backend.Read(id)

	if err != nil {
		raiseHTTPError(w, &HTTPError{
			Message:  "Share-d was unable to read the secret with ID: " + id,
			Cause:    err,
			HTTPCode: 500,
		})
		return
	}

	output, err := json.Marshal(secret)

	if err != nil {
		raiseHTTPError(w, &HTTPError{
			Message:  "There was an error while reading the secret with ID: " + id,
			Cause:    err,
			HTTPCode: 500,
		})
		return
	}

	w.Write(output)

}

func addSecret(w http.ResponseWriter, r *http.Request) {

	request := r.Body
	requestBody, err := ioutil.ReadAll(request)

	if err != nil {
		raiseHTTPError(w, &HTTPError{
			HTTPCode: 401,
			Message:  "Unable to read the provided secret",
			Cause:    err,
		})
		return
	}

	var secret secrets.Secret

	json.Unmarshal(requestBody, &secret)

	if secret.EncryptedValue == "" {
		raiseHTTPError(w, &HTTPError{
			HTTPCode: 400,
			Message:  "Encrypted Value must be provided",
		})
		return
	}

	metadata, err := server.Backend.Save(secret)

	if type(err) == backends.SecretAlreadyExistsError {
		raiseHTTPError(w, &HTTPError{
			HTTPCode: 409,
			Message:  "Secret with the given ID already exists",
		})
		return
	} else if err != nil {
		raiseHTTPError(w, &HTTPError{
			HTTPCode: 500,
			Message:  "Share-d was unable to store the provided secret",
			Cause:    err,
		})
		return
	}

	output, _ := json.Marshal(&secret)
	w.Write(output)
}

func replaceSecret(w http.ResponseWriter, r *http.Request) {

	params := httprouter.ParamsFromContext(r.Context())
	id := params.ByName("id")

	request := r.Body
	requestBody, err := ioutil.ReadAll(request)

	if err != nil {
		raiseHTTPError(w, &HTTPError{
			HTTPCode: 401,
			Message:  "Unable to read the provided secret",
			Cause:    err,
		})
		return
	}

	var secret secrets.Secret

	json.Unmarshal(requestBody, &secret)

	if secret.EncryptedValue == "" {
		raiseHTTPError(w, &HTTPError{
			HTTPCode: 400,
			Message:  "Encrypted Value must be provided",
		})
		return
	}

	if info, _ := os.Stat(config.Backend + "/" + id); info != nil {
		file, err := os.Open(config.Backend + "/" + id)
		defer file.Close()
		if err != nil {
			raiseHTTPError(w, &HTTPError{
				HTTPCode: 500,
				Message:  "An unexpected error occured",
				Cause:    err,
			})
			return
		}
		// can ignore error here since we just unmarshalled it from JSON
		output, _ := json.Marshal(&secret)
		_, err = file.Write(output)
		if err != nil {
			raiseHTTPError(w, &HTTPError{
				HTTPCode: 500,
				Message:  "Share-d was unable to store the provided secret",
				Cause:    err,
			})
			return
		}

		w.Write(output)
	} else {
		raiseHTTPError(w, &HTTPError{
			HTTPCode: 409,
			Message:  "Secret with the given ID does not exist",
		})
		return
	}
}

func updateSecret(w http.ResponseWriter, r *http.Request) {
	params := httprouter.ParamsFromContext(r.Context())
	id := params.ByName("id")

	request := r.Body
	requestBody, err := ioutil.ReadAll(request)

	if err != nil {
		raiseHTTPError(w, &HTTPError{
			HTTPCode: 401,
			Message:  "Unable to read the provided secret",
			Cause:    err,
		})
		return
	}

	var secret secrets.Secret

	json.Unmarshal(requestBody, &secret)

	if info, _ := os.Stat(config.Backend + "/" + id); info != nil {
		file, err := os.OpenFile(config.Backend+"/"+id, os.O_RDWR, 0666)
		defer file.Close()

		if err != nil {
			raiseHTTPError(w, &HTTPError{
				HTTPCode: 500,
				Message:  "An unexpected error occured",
				Cause:    err,
			})
			return
		}

		secretBytes, err := ioutil.ReadAll(file)
		var existingSecret secrets.Secret
		err = json.Unmarshal(secretBytes, &existingSecret)

		if secret.EncryptedValue == "" {
			secret.EncryptedValue = existingSecret.EncryptedValue
		}
		if secret.PrivateKeyAlias == "" {
			secret.PrivateKeyAlias = existingSecret.PrivateKeyAlias
		}
		if secret.EncryptedSymmetricKey == nil {
			secret.EncryptedSymmetricKey = existingSecret.EncryptedSymmetricKey
		}
		if existingSecret.EncryptedSymmetricKey != nil {
			if secret.EncryptedSymmetricKey.Algorithm == "" {
				secret.EncryptedSymmetricKey.Algorithm = existingSecret.EncryptedSymmetricKey.Algorithm
			}
			if secret.EncryptedSymmetricKey.Method == "" {
				secret.EncryptedSymmetricKey.Method = existingSecret.EncryptedSymmetricKey.Method
			}
			if secret.EncryptedSymmetricKey.Padding == "" {
				secret.EncryptedSymmetricKey.Padding = existingSecret.EncryptedSymmetricKey.Padding
			}
			if secret.EncryptedSymmetricKey.Value == "" {
				secret.EncryptedSymmetricKey.Value = existingSecret.EncryptedSymmetricKey.Value
			}
		}

		// can ignore error here since we just unmarshalled it from JSON
		output, _ := json.Marshal(&secret)
		_, err = file.Write(output)
		if err != nil {
			raiseHTTPError(w, &HTTPError{
				HTTPCode: 500,
				Message:  "Share-d was unable to store the provided secret",
				Cause:    err,
			})
			return
		}

		w.Write(output)
	} else {
		raiseHTTPError(w, &HTTPError{
			HTTPCode: 409,
			Message:  "Secret with the given ID does not exist",
		})
		return
	}
}

func deleteSecret(w http.ResponseWriter, r *http.Request) {
	params := httprouter.ParamsFromContext(r.Context())
	id := params.ByName("id")

	if err := os.Remove(config.Backend + "/" + id); os.IsNotExist(err) {
		raiseHTTPError(w, &HTTPError{
			HTTPCode: 404,
			Message:  "Secret with id " + id + " does not exist",
			Cause:    err,
		})
		return
	} else if err != nil {
		raiseHTTPError(w, &HTTPError{
			HTTPCode: 500,
			Message:  "Unable to remove secret with id " + id,
			Cause:    err,
		})
		return
	}
	w.WriteHeader(200)
}

func raiseHTTPError(w http.ResponseWriter, err *HTTPError) {
	ErrorLogger.Println(err.Cause)

	output, outputErr := json.Marshal(err)
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if outputErr != nil {
		ErrorLogger.Println(outputErr)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(w, "There was an unexpected error", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(err.HTTPCode)
	w.Write(output)
}
