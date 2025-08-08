package jsonutil

import (
	"encoding/json"
	"errors"
	"io"
	"os"
)

// Load reads JSON at path into a fresh value of T and returns it.
func Load[T any](path string) (T, error) {
	var zero T

	f, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer f.Close()

	var v T
	err = json.NewDecoder(f).Decode(&v)
	if err != nil && !errors.Is(err, io.EOF) {
		return zero, err
	}
	return v, nil
}

// Save writes v to path atomically (tmp file + rename).
func Save[T any](path string, v T) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}
