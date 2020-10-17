package backends

import (
	"github.com/elliottpope/share-d/secrets"
)

// Backend ... interface for making interactions with persistent stores
type Backend interface {
	List() ([]secrets.SecretMetadata, error)
	Save(secret secrets.Secret) (*secrets.SecretMetadata, error)
	Read(id string) (*secrets.Secret, error)
	Update(location string, secret secrets.Secret) (*secrets.Secret, error)
	Replace(location string, secret secrets.Secret) (*secrets.Secret, error)
	Delete(location string) error
}

// SecretAlreadyExistsError ... error to be thrown if you're trying to overwrite an existing secret
type SecretAlreadyExistsError struct {
	ID       string
	Location string
}

func (err *SecretAlreadyExistsError) Error() string {
	return "Secret (" + err.ID + ") already exists at " + err.Location
}

// SecretDoesNotExistError ... error to be thrown if you're trying to overwrite an existing secret
type SecretDoesNotExistError struct {
	ID       string
	Location string
}

func (err *SecretDoesNotExistError) Error() string {
	return "Secret (" + err.ID + ") does not exist at " + err.Location
}
