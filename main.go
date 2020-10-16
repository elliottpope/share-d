package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/elliottpope/share-d/backends"

	"github.com/elliottpope/share-d/secrets"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
)

// HTTPError ... encapsulates details of an HTTP Error to be raised and displayed to the client
type HTTPError struct {
	HTTPCode int    `json:"-"`
	Message  string `json:"error-message"`
	Code     string `json:"error-code,omitempty"`
	Cause    error  `json:"-"`
}

// Configuration ... data structure for holding the confguration of the Share-d server
type Configuration struct {
	Backend string
}

var (
	config  *Configuration = &Configuration{}
	backend *backends.Backend

	// ErrorLogger ... global error logger
	ErrorLogger *log.Logger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
)

func main() {
	backendLocation := flag.String("backend", "./data", "the location to store secrets and metadata")

	flag.Parse()

	config.Backend = *backendLocation

	if _, err := os.Stat(*backendLocation); os.IsNotExist(err) {
		os.Mkdir(*backendLocation, 0666)
	}

	backend := &backends.FileBackend{
		BasePath: config.Backend,
	}

	router := registerEndpoints()
	startServer(router)

}

func registerEndpoints() *httprouter.Router {
	router := httprouter.New()

	router.HandlerFunc("LIST", "/secrets", listSecrets)
	router.HandlerFunc("GET", "/secrets/:id", getSecret)
	router.HandlerFunc("POST", "/secrets", addSecret)
	router.HandlerFunc("PUT", "/secrets/:id", replaceSecret)
	router.HandlerFunc("PATCH", "/secrets/:id", updateSecret)
	router.HandlerFunc("DELETE", "/secrets/:id", deleteSecret)

	return router
}

func startServer(router *httprouter.Router) {
	log.Fatal(http.ListenAndServe(":8080", router))
}

func listSecrets(w http.ResponseWriter, r *http.Request) {

	metadata, err := backend.List()
	files, err := ioutil.ReadDir(config.Backend)
	if err != nil {
		raiseHTTPError(w, &HTTPError{
			Message:  "There was an error while finding secrets",
			Cause:    err,
			HTTPCode: 500,
		})
		return
	}

	var metadata = make([]secrets.SecretMetadata, len(files))
	for i, file := range files {
		metadata[i] = secrets.SecretMetadata{
			ID: file.Name(),
		}
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

func getSecret(w http.ResponseWriter, r *http.Request) {
	params := httprouter.ParamsFromContext(r.Context())
	id := params.ByName("id")

	file, err := os.Open(config.Backend + "/" + id)
	defer file.Close()

	if err != nil {
		raiseHTTPError(w, &HTTPError{
			Message:  "Share-d was unable to locate the secret with ID: " + id,
			Cause:    err,
			HTTPCode: 404,
		})
		return
	}

	secretBytes, err := ioutil.ReadAll(file)
	var secret secrets.Secret
	err = json.Unmarshal(secretBytes, &secret)

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

	id := uuid.New()

	if _, err := os.Stat(config.Backend + "/" + id.String()); os.IsNotExist(err) {
		file, err := os.Create(config.Backend + "/" + id.String())
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
			Message:  "Secret with the given ID already exists",
		})
		return
	}
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