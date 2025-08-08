linknife

A tiny self-hosted URL-shortener written in Go.
	•	Flat layout — every package lives one directory deep (no cmd/, no internal/).
	•	BoltDB storage (single file, zero external deps).
	•	Admin + user API keys with per-permission flags.
	•	10-second landing/redirect page with cancel tracking.
	•	CLI utilities to manage keys, run the server and dump stats.

⸻

Quick start

# clone & fetch deps
$ git clone https://github.com/yourname/linknife && cd linknife && go mod tidy

# 1. create minimal config & empty users file
$ echo '{ "port":8080, "db_path":"./data/linknife.db" }' > config.json
$ echo '{}' > users.json

# 2. generate an admin key and inject it into config.json
$ go run . apikey admin --config config.json

# 3. (optional) generate a user key with all perms
$ go run . apikey user generate --users users.json --create --update --delete

# 4. start the server
$ go run . serve --config config.json

Server is now listening at http://localhost:8080.

⸻

File layout

.
```bash
├── main.go         # CLI entry-point (Cobra)
├── server/         # HTTP handlers + Bolt logic
├── apikeygen/      # key generation & JSON mutators
├── jsonutil/       # tiny generic JSON load/save
├── go.mod
├── go.sum
└── README.md
```

⸻

Config files

config.json
```json
{
  "admin_api_key": "",
  "db_path": "linknife.db",
  "log_path": "linknife.log",
  "port": 8080,
  "tls_cert": "cert.pem",
  "tls_key": "key.pem",
  "tls_port": 0,
  "users_file": "users.json"
}
```

users.json
```json
{
  "<128-hex-key>": {
    "api_key": "<same-key>",
    "perm": {
      "create": true,
      "change": true,
      "delete": false
    }
  }
}
```

⸻

CLI reference

### Command	Purpose

linknife serve --config config.json	start HTTP/HTTPS server
linknife apikey admin --config config.json	generate one admin key
linknife apikey user generate --users users.json [--create] [--update] [--delete]	new user key
linknife apikey user edit <key> --users users.json [--create] [--update] [--delete]	modify perms
linknife apikey user delete <key> --users users.json	remove a key
linknife apikey user list --users users.json	list all user keys
linknife stats --config config.json	global link/visit stats

Flags omitted on generate/edit default to false.

⸻

HTTP API

All JSON is UTF-8; auth via header X-API-Key: … or query ?api_key=.

1  Shorten

curl -H "X-API-Key: $USER_KEY" -d '{"url":"https://example.com"}' http://localhost:8080/api/shorten

→ { "short_url": "http://…/1a2b3c4d", "code": "1a2b3c4d" }

2  Update

curl -H "X-API-Key: $USER_KEY" -d '{"url":"https://new.example.com"}' http://localhost:8080/api/update/1a2b3c4d

3  Delete code

curl -X POST -H "X-API-Key: $USER_KEY" http://localhost:8080/api/remove/1a2b3c4d

4  Per-link stats

curl "http://localhost:8080/1a2b3c4d/stats?api_key=$ADMIN_KEY"

5  Cancel redirect (auto-triggered by landing page)

curl -X POST http://localhost:8080/api/cancel/1a2b3c4d

6  Redirect page (browser visit)

GET /1a2b3c4d → 10-second splash then 302.

⸻

Build static binary

go build -trimpath -ldflags="-s -w" -o linknife .


⸻

Backup
	•	BoltDB (db_path) is a single file — stop server or copy atomically.
	•	users.json & config.json are plain text.
