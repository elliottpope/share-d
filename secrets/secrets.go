package secrets

// Secret ... defines the value of an encrypted secret to be stored along with information about how it is encrypted.
type Secret struct {
	EncryptedValue        string        `json:"value"`
	EncryptedSymmetricKey *SymmetricKey `json:"symmetric-key,omitempty"`
	PrivateKeyAlias       string        `json:"private-key-alias,omitempty"`
}

// SecretMetadata ... defines the metadata for locating or listing the secrets for a given user/org/team. Provides the location of the actual secret in the backend.
type SecretMetadata struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"-"`
}

// SymmetricKey ... defines an encryption key along with the necessary metadata for a client to use it.
type SymmetricKey struct {
	Algorithm string `json:"alg,omitempty"`
	Method    string `json:"method,omitempty"`
	Padding   string `json:"padding,omitempty"`
	Value     string `json:"value,omitempty"`
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
