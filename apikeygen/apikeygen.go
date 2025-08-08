package apikeygen

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"linknife/jsonutil"
)

/*───────────────────────────── TYPES ──────────────────────────────*/

// UserPerm mirrors the structure linknife’s server expects in users.json.
type UserPerm struct {
	Create bool `json:"create"`
	Change bool `json:"change"`
	Delete bool `json:"delete"`
}

/*──────────────────────── KEY GENERATION ──────────────────────────*/

// Generate returns a cryptographically-secure 128-char hex API key.
func Generate() string {
	buf := make([]byte, 64) // 512 bits of entropy
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Errorf("entropy: %w", err))
	}
	sum := sha512.Sum512(buf)
	return hex.EncodeToString(sum[:])
}

/*─────────────────────── JSON HELPERS ─────────────────────────────*/

func loadMap(path string) (map[string]any, error) {
	m, err := jsonutil.Load[map[string]any](path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return map[string]any{}, nil // treat missing file as empty map
	case err != nil:
		return nil, err
	default:
		if m == nil {
			m = map[string]any{}
		}
		return m, nil
	}
}

/*──────────────────── ADMIN-KEY WORKFLOW ──────────────────────────*/

// SetAdminKey writes a freshly-generated key into
// the “admin_api_key” field of cfgPath and returns that key.
func SetAdminKey(cfgPath string) (string, error) {
	key := Generate()

	cfg, err := loadMap(cfgPath)
	if err != nil {
		return "", fmt.Errorf("load config: %w", err)
	}
	cfg["admin_api_key"] = key
	if err := jsonutil.Save(cfgPath, cfg); err != nil {
		return "", fmt.Errorf("save config: %w", err)
	}
	return key, nil
}

/*──────────────────── USER-KEY WORKFLOW ───────────────────────────*/

// AddUserKey appends a new user entry to usersPath and returns the key.
func AddUserKey(usersPath string, perm UserPerm) (string, error) {
	key := Generate()

	users, err := loadMap(usersPath)
	if err != nil {
		return "", fmt.Errorf("load users: %w", err)
	}
	users[key] = map[string]any{
		"api_key": key,
		"perm": map[string]bool{
			"create": perm.Create,
			"change": perm.Change,
			"delete": perm.Delete,
		},
	}
	if err := jsonutil.Save(usersPath, users); err != nil {
		return "", fmt.Errorf("save users: %w", err)
	}
	return key, nil
}

// UpdateUserPerms overwrites the perm block for an existing key.
func UpdateUserPerms(usersPath, key string, perm UserPerm) error {
	users, err := loadMap(usersPath)
	if err != nil {
		return err
	}
	entry, ok := users[key].(map[string]any)
	if !ok {
		return fmt.Errorf("key not found")
	}
	entry["perm"] = map[string]bool{
		"create": perm.Create,
		"change": perm.Change,
		"delete": perm.Delete,
	}
	users[key] = entry
	return jsonutil.Save(usersPath, users)
}

// RemoveUserKey deletes key from users.json.
func RemoveUserKey(usersPath, key string) error {
	users, err := loadMap(usersPath)
	if err != nil {
		return err
	}
	if _, ok := users[key]; !ok {
		return fmt.Errorf("key not found")
	}
	delete(users, key)
	return jsonutil.Save(usersPath, users)
}

// ListUsers returns every key in users.json with its permissions.
func ListUsers(usersPath string) (map[string]UserPerm, error) {
	raw, err := loadMap(usersPath)
	if err != nil {
		return nil, err
	}

	out := make(map[string]UserPerm, len(raw))
	for k, v := range raw {
		entry, ok := v.(map[string]any)
		if !ok {
			continue
		}
		p, ok := entry["perm"].(map[string]any)
		if !ok {
			continue
		}
		out[k] = UserPerm{
			Create: p["create"] == true,
			Change: p["change"] == true,
			Delete: p["delete"] == true,
		}
	}
	return out, nil
}
