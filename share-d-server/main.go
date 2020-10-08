package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

// Secret ... defines the value of an encrypted secret to be stored along with information about how it is encrypted.
type Secret struct {
	EncryptedValue        string       `json:"value"`
	EncryptedSymmetricKey SymmetricKey `json:"symmetric-key"`
	PrivateKeyAlias       string       `json:"private-key-alias"`
}

// SecretMetadata ... defines the metadata for locating or listing the secrets for a given user/org/team. Provides the location of the actual secret in the backend.
type SecretMetadata struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"-"`
}

// SymmetricKey ... defines an encryption key along with the necessary metadata for a client to use it.
type SymmetricKey struct {
	Algorithm string `json:"alg"`
	Method    string `json:"method"`
	Padding   string `json:"padding"`
	Value     string `json:"value"`
}

// Algorithm ... returns the full algorithm for using the key to encrypt or decrypt. e.g. AES/GCM/NoPadding
func Algorithm(key *SymmetricKey) string {
	return key.Algorithm + "/" + key.Method + "/" + key.Padding
}

// Value ... returns to Base64 encoded value of the symmetric key. Note, if passed over the network this value will be encrypted.
func Value(key *SymmetricKey) string {
	return key.Value
}

// Key ... defines an interface that all keys must implement
type Key interface {
	Value() string
	Algorithm() string
}

// Configuration ... data structure for holding the confguration of the Share-d server
type Configuration struct {
	Backend string
}

var config *Configuration = &Configuration{}

func main() {
	backendLocation := flag.String("backend", "./", "the location to store secrets and metadata")

	flag.Parse()

	config.Backend = *backendLocation

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
	files, err := ioutil.ReadDir(config.Backend)
	if err != nil {
		log.Fatal(err)
		http.Error(w, "There was an error while finding secrets", 500)
		return
	}

	var secrets = make([]SecretMetadata, len(files))
	for i, file := range files {
		secrets[i] = SecretMetadata{
			ID: file.Name(),
		}
	}

	output, err := json.Marshal(secrets)

	if err != nil {
		log.Fatal(err)
		http.Error(w, "There was an error while finding secrets", 500)
		return
	}

	w.Write(output)
}

func getSecret(w http.ResponseWriter, r *http.Request) {

}

func addSecret(w http.ResponseWriter, r *http.Request) {

}

func replaceSecret(w http.ResponseWriter, r *http.Request) {

}

func updateSecret(w http.ResponseWriter, r *http.Request) {

}

func deleteSecret(w http.ResponseWriter, r *http.Request) {

}
