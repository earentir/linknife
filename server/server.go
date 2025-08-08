package server

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"linknife/jsonutil"
)

/*──────────────────────────────── CONFIG ───────────────────────────────*/
var Cfg struct {
	Port            int    `mapstructure:"port"  json:"port"`
	TLSPort         int    `mapstructure:"tls_port"  json:"tls_port"`
	TLSCert         string `mapstructure:"tls_cert"  json:"tls_cert"`
	TLSKey          string `mapstructure:"tls_key"   json:"tls_key"`
	TLSIntermediate string `mapstructure:"tls_intermediate" json:"tls_intermediate"`

	DBPath      string `mapstructure:"db_path"  json:"db_path"`
	LogPath     string `mapstructure:"log_path" json:"log_path"`
	UsersFile   string `mapstructure:"users_file" json:"users_file"`
	AdminAPIKey string `mapstructure:"admin_api_key" json:"admin_api_key"`
}

/*───────────────────────── PACKAGE-LEVEL STATE ─────────────────────────*/
var (
	logger *log.Logger

	db     *bolt.DB
	dbOnce sync.Once

	users      map[string]User
	usersMutex sync.RWMutex
)

/*───────────────────────────── LOGGER ─────────────────────────────────*/
func setupLogger(path string) {
	w := []io.Writer{os.Stdout}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			log.Fatalf("log-file: %v", err)
		}
		w = append(w, f)
	}
	logger = log.New(io.MultiWriter(w...), "", log.LstdFlags|log.LUTC)
}

/*───────────────────────────── BOLT DB ────────────────────────────────*/
func openDB(path string) {
	dbOnce.Do(func() {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			log.Fatalf("db-dir: %v", err)
		}
		var err error
		db, err = bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
		if err != nil {
			log.Fatalf("open Bolt: %v", err)
		}
		if err := db.Update(func(tx *bolt.Tx) error {
			_, e := tx.CreateBucketIfNotExists([]byte("urls"))
			return e
		}); err != nil {
			log.Fatalf("bucket: %v", err)
		}
	})
}

/*────────────────────────────── USERS ─────────────────────────────────*/
type Perm struct{ Create, Change, Delete bool }
type User struct {
	APIKey string `json:"api_key"`
	Perm   Perm   `json:"perm"`
}

func loadUsers(path string) {
	u, err := jsonutil.Load[map[string]User](path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		u = make(map[string]User)
		_ = jsonutil.Save(path, u)
	case err != nil:
		log.Fatalf("users: %v", err)
	}
	usersMutex.Lock()
	users = u
	usersMutex.Unlock()
}

func saveUsers(path string) {
	usersMutex.RLock()
	defer usersMutex.RUnlock()
	if err := jsonutil.Save(path, users); err != nil {
		logger.Fatalf("save users: %v", err)
	}
}

func keyID(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])
}

/*──────────────────────── URL META IN BOLT ───────────────────────────*/
type URLMeta struct {
	OriginalURL string        `json:"original_url"`
	OwnerID     string        `json:"owner_id"`
	CreatedAt   time.Time     `json:"created_at"`
	Visits      uint64        `json:"visits"`
	Redirects   uint64        `json:"redirects"`
	Cancels     uint64        `json:"cancels"`
	Visitors    []VisitRecord `json:"visitors"` // capped at 50
}
type VisitRecord struct {
	IP        string    `json:"ip"`
	UserAgent string    `json:"ua"`
	Time      time.Time `json:"t"`
}

func saveURL(code string, meta *URLMeta) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("urls"))
		j, _ := json.Marshal(meta)
		return b.Put([]byte(code), j)
	})
}
func getURL(code string) (*URLMeta, error) {
	var m URLMeta
	err := db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte("urls")).Get([]byte(code))
		if v == nil {
			return os.ErrNotExist
		}
		return json.Unmarshal(v, &m)
	})
	return &m, err
}
func deleteURL(code string) error {
	return db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("urls")).Delete([]byte(code))
	})
}

/*──────────────────────────── HELPERS ───────────────────────────────*/
func randomSHA1() string {
	var b [20]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	sum := sha1.Sum(b[:])
	return hex.EncodeToString(sum[:])[:8]
}
func genAPIKey() string {
	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	sum := sha512.Sum512(b[:])
	return hex.EncodeToString(sum[:])
}
func getIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

/*──────────────────── AUTH MIDDLEWARE & HELPERS ─────────────────────*/
type ctxKey string

const keyUser ctxKey = "user"

func auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			apiKey = r.URL.Query().Get("api_key")
		}
		if apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}
		if apiKey == Cfg.AdminAPIKey {
			ctx := context.WithValue(r.Context(), keyUser, "admin")
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		usersMutex.RLock()
		u, ok := users[apiKey]
		usersMutex.RUnlock()
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api_key"})
			return
		}
		ctx := context.WithValue(r.Context(), keyUser, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func currentUser(r *http.Request) (User, bool) {
	v := r.Context().Value(keyUser)
	if v == nil {
		return User{}, false
	}
	switch vv := v.(type) {
	case string: // admin
		return User{APIKey: Cfg.AdminAPIKey, Perm: Perm{Create: true, Change: true, Delete: true}}, true
	case User:
		return vv, true
	default:
		return User{}, false
	}
}

/*───────────────────── JSON RESPONSE HELPER ─────────────────────────*/
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

/*────────────────────────── API HANDLERS ───────────────────────────*/
func shortenHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing api_key"})
		return
	}
	if !user.Perm.Create {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no create permission"})
		return
	}
	type req struct {
		URL    string `json:"url"`
		Custom string `json:"custom,omitempty"`
	}
	var body req
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	code := body.Custom
	if code == "" {
		code = randomSHA1()
	}
	ownerID := keyID(user.APIKey)
	meta := &URLMeta{
		OriginalURL: body.URL,
		OwnerID:     ownerID,
		CreatedAt:   time.Now().UTC(),
	}
	if err := saveURL(code, meta); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	shortURL := fmt.Sprintf("%s://%s/%s", scheme, r.Host, code)
	writeJSON(w, http.StatusOK, map[string]string{
		"short_url": shortURL,
		"code":      code,
	})
}

func updateHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing api_key"})
		return
	}
	if !user.Perm.Change {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no change permission"})
		return
	}
	code := strings.TrimPrefix(r.URL.Path, "/api/update/")
	meta, err := getURL(code)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	ownerID := keyID(user.APIKey)
	if ownerID != meta.OwnerID && user.APIKey != Cfg.AdminAPIKey {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "not owner"})
		return
	}
	type req struct {
		URL string `json:"url"`
	}
	var body req
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	meta.OriginalURL = body.URL
	if err := saveURL(code, meta); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func removeHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing api_key"})
		return
	}
	if !user.Perm.Delete {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no delete permission"})
		return
	}
	code := strings.TrimPrefix(r.URL.Path, "/api/remove/")
	meta, err := getURL(code)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	ownerID := keyID(user.APIKey)
	if ownerID != meta.OwnerID && user.APIKey != Cfg.AdminAPIKey {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "not owner"})
		return
	}
	if err := deleteURL(code); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/stats")
	meta, err := getURL(code)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		apiKey = r.URL.Query().Get("api_key")
	}
	if apiKey != Cfg.AdminAPIKey && keyID(apiKey) != meta.OwnerID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

func cancelHandler(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimPrefix(r.URL.Path, "/api/cancel/")
	meta, err := getURL(code)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	meta.Cancels++
	meta.Visits++
	if len(meta.Visitors) >= 50 {
		meta.Visitors = meta.Visitors[1:]
	}
	meta.Visitors = append(meta.Visitors, VisitRecord{
		IP:        getIP(r),
		UserAgent: r.UserAgent(),
		Time:      time.Now().UTC(),
	})
	_ = saveURL(code, meta)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancel recorded"})
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimPrefix(r.URL.Path, "/")
	if strings.HasSuffix(code, "/stats") {
		statsHandler(w, r)
		return
	}
	meta, err := getURL(code)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	meta.Visits++
	meta.Redirects++
	if len(meta.Visitors) >= 50 {
		meta.Visitors = meta.Visitors[1:]
	}
	meta.Visitors = append(meta.Visitors, VisitRecord{
		IP:        getIP(r),
		UserAgent: r.UserAgent(),
		Time:      time.Now().UTC(),
	})
	_ = saveURL(code, meta)

	tmpl := `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Redirecting…</title>
<script>
let t = 10;
function tick(){
  if(t<=0){ window.location = %q; return;}
  document.getElementById('timer').textContent=t;
  t--;
}
setInterval(tick,1000);
</script>
</head><body style="font-family:sans-serif;text-align:center;padding:40px">
<h1>Ready to go!</h1>
<p>Destination: <a href=%q target="_blank">%q</a></p>
<p>Redirecting in <span id="timer">10</span> s…</p>
<button onclick="fetch('/api/cancel/%s',{method:'POST'}).then(()=>{clearInterval();document.getElementById('timer').textContent='cancelled'})">Cancel Redirect</button>
</body></html>`
	html := fmt.Sprintf(tmpl, meta.OriginalURL, meta.OriginalURL, meta.OriginalURL, code)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

/*────────────────── mux & server bootstrap helpers ─────────────────*/
func newMux() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/api/shorten", shortenHandler)
	m.HandleFunc("/api/update/", updateHandler)
	m.HandleFunc("/api/remove/", removeHandler)
	m.HandleFunc("/api/cancel/", cancelHandler)
	m.HandleFunc("/", redirectHandler)
	return auth(m)
}

func run(ctx context.Context, addr string, h http.Handler, tls bool) error {
	srv := &http.Server{Addr: addr, Handler: h}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	if tls {
		return srv.ListenAndServeTLS(Cfg.TLSCert, Cfg.TLSKey)
	}
	return srv.ListenAndServe()
}

/*──────────────────── PUBLIC ENTRYPOINT ───────────────────────────*/
func Serve(parent context.Context) error {
	setupLogger(Cfg.LogPath)
	openDB(Cfg.DBPath)
	loadUsers(Cfg.UsersFile)

	handler := newMux()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	errs := make(chan error, 2)
	if Cfg.Port > 0 {
		go func() { errs <- run(ctx, fmt.Sprintf(":%d", Cfg.Port), handler, false) }()
	}
	if Cfg.TLSPort > 0 && Cfg.TLSCert != "" && Cfg.TLSKey != "" {
		go func() { errs <- run(ctx, fmt.Sprintf(":%d", Cfg.TLSPort), handler, true) }()
	}
	if Cfg.Port == 0 && Cfg.TLSPort == 0 {
		return errors.New("both port and tls_port are zero – nothing to serve")
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-errs:
		return err
	}
}
