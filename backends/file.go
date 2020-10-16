package backends

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/elliottpope/share-d/secrets"
	"github.com/google/uuid"
)

// FileBackend ... simple backend for a file store
type FileBackend struct {
	BasePath string
}

// Save ... saves the given secret
func (fs *FileBackend) Save(secret secrets.Secret) (*secrets.SecretMetadata, error) {
	id := uuid.New()

	if _, err := os.Stat(fs.BasePath + "/" + id.String()); os.IsNotExist(err) {
		file, err := os.Create(fs.BasePath + "/" + id.String())
		if err != nil {
			return nil, err
		}
		// can ignore error here since we just unmarshalled it from JSON
		output, _ := json.Marshal(&secret)
		_, err = file.Write(output)
		if err != nil {
			return nil, err
		}
		return &secrets.SecretMetadata{
			ID:       id.String(),
			Location: id.String(),
			Name:     id.String(),
		}, nil
	}

	return nil, &SecretAlreadyExistsError{
		ID:       id.String(),
		Location: fs.BasePath + "/" + id.String(),
	}
}

// Read ... read secret with the given ID in fielsystem
func (fs *FileBackend) Read(id string) (*secrets.Secret, error) {
	file, err := os.Open(fs.BasePath + "/" + id)
	defer file.Close()

	if err != nil {
		return nil, err
	}

	secretBytes, err := ioutil.ReadAll(file)
	var secret secrets.Secret
	if err = json.Unmarshal(secretBytes, &secret); err != nil {
		return nil, err
	}

	return &secret, nil
}

// Update ... update field by field the given secret in the given location
func (fs *FileBackend) Update(location string, secret secrets.Secret) secrets.Secret {
	panic("not implemented") // TODO: Implement
}

// Replace ... replace the secret at the given location with the given secret
func (fs *FileBackend) Replace(location string, secret secrets.Secret) secrets.Secret {
	panic("not implemented") // TODO: Implement
}

// Delete ... remove the secret at the given location
func (fs *FileBackend) Delete(location string) bool {
	panic("not implemented") // TODO: Implement
}

// List ... list all of the secrets in the fiel system backend
func (fs *FileBackend) List() ([]secrets.SecretMetadata, error) {
	files, err := ioutil.ReadDir(fs.BasePath)
	if err != nil {
		return nil, err
	}

	var metadata = make([]secrets.SecretMetadata, len(files))
	for i, file := range files {
		metadata[i] = secrets.SecretMetadata{
			ID: file.Name(),
		}
	}

	return metadata, nil
}
