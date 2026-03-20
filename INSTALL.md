# EncMind Installation Guide

## Prerequisites

- Rust 1.80+ (`cargo`)
- A strong passphrase for `ENCMIND_PASSPHRASE`
- An LLM API key (for example `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`)

---

## Choose Your Deployment Path

| Path | Use when | Setup profile | Transport |
|---|---|---|---|
| Local | Single machine / localhost development | `local` | `ws://localhost:8443` |
| Remote | VM, NAS, LAN host, or Tailscale host | `remote` | `wss://<ip>:8443` (auto-TLS, TOFU pinning) |
| Domain | Public domain with real certs | `domain` | `wss://<domain>` |

---

## Quick Start: Local

```bash
git clone <repo-url> encmind
cd encmind

brew install --cask docker-desktop
docker run -d -p 6333:6333 -p 6334:6334 -v qdrant_data:/qdrant/storage qdrant/qdrant
docker --version
open -a Docker

export ENCMIND_PASSPHRASE="pick-a-strong-passphrase"
./install.sh --profile local

# optional if ~/.encmind/bin is not already on PATH
export PATH="$HOME/.encmind/bin:$PATH"
export ANTHROPIC_API_KEY="sk-ant-..."

# install.sh already ran setup; now start the server
encmind-core serve
```

Build-speed notes:
- First run can take a while (Rust compilation).
- Repeat install without rebuild:
  - `./install.sh --profile local --skip-rust-build`
- If you really need every crate rebuilt, use `--workspace-build`.

In another terminal:

```bash
encmind-edge pair --name "my-laptop"
encmind-edge connect
```

---

## Quick Start: Remote (VM / NAS / LAN / Tailscale)

On the server:

```bash
git clone <repo-url> encmind
cd encmind

export ENCMIND_PASSPHRASE="pick-a-strong-passphrase"
./install.sh --profile remote

# optional if ~/.encmind/bin is not already on PATH
export PATH="$HOME/.encmind/bin:$PATH"
export ANTHROPIC_API_KEY="sk-ant-..."

# install.sh already ran setup; now start the server
encmind-core serve
```

Open firewall port `8443/tcp` (for example `sudo ufw allow 8443/tcp`).

On the client:

```bash
encmind-edge --gateway wss://<server-ip>:8443 pair --name "my-laptop"
encmind-edge --gateway wss://<server-ip>:8443 connect
```

First TLS connection behavior:
- `encmind-edge` shows a trust prompt with the server fingerprint (TOFU).
- On approval, the fingerprint is pinned in `~/.encmind-edge/known_hosts`.
- You can still provide `--fingerprint SHA256:...` explicitly if you want strict non-interactive pinning.

---

## Quick Start: Domain (Public TLS)

On the server:

### Option A: ACME (Let's Encrypt)

```bash
git clone <repo-url> encmind
cd encmind

export ENCMIND_PASSPHRASE="pick-a-strong-passphrase"
./install.sh --profile domain \
  --acme-domain assistant.example.com \
  --acme-email ops@example.com

# optional if ~/.encmind/bin is not already on PATH
export PATH="$HOME/.encmind/bin:$PATH"
export ANTHROPIC_API_KEY="sk-ant-..."

# install.sh already ran setup; now start the server
encmind-core serve
```

### Option B: Bring your own certificate

```bash
git clone <repo-url> encmind
cd encmind

export ENCMIND_PASSPHRASE="pick-a-strong-passphrase"
./install.sh --profile domain \
  --tls-cert-path /etc/letsencrypt/live/example.com/fullchain.pem \
  --tls-key-path /etc/letsencrypt/live/example.com/privkey.pem

# optional if ~/.encmind/bin is not already on PATH
export PATH="$HOME/.encmind/bin:$PATH"
export ANTHROPIC_API_KEY="sk-ant-..."

# install.sh already ran setup; now start the server
encmind-core serve
```

Client connection:

```bash
encmind-edge --gateway wss://assistant.example.com pair --name "my-laptop"
```

Notes:
- Domain setup defaults to port `443`.
- If you changed port in config, include it explicitly:
  - `wss://assistant.example.com:<port>`

---

## LLM Configuration

`install.sh` runs `encmind-core setup` for the selected profile and creates a baseline config.
You still need model/provider config in `~/.encmind/config.yaml`.

Anthropic example:

```yaml
llm:
  mode:
    type: ApiProvider
    provider: anthropic
  api_providers:
    - name: anthropic
      model: claude-sonnet-4-20250514
```

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

OpenAI example:

```yaml
llm:
  mode:
    type: ApiProvider
    provider: openai
  api_providers:
    - name: openai
      model: gpt-4o
```

```bash
export OPENAI_API_KEY="sk-..."
```

---

## Slack Integration

Add a Slack channel adapter so the assistant can receive and reply to messages in Slack.

### 1. Create a Slack App

1. Go to [api.slack.com/apps](https://api.slack.com/apps) and create a new app
2. Enable **Socket Mode** (Settings → Socket Mode → Enable)
3. Add the **Bot Token Scopes** under OAuth & Permissions:
   - `chat:write`
   - `app_mentions:read`
   - `im:history`
   - `im:read`
   - `im:write`
4. Subscribe to **Event Subscriptions**:
   - `message.im` (direct messages to the bot)
   - `app_mention` (mentions in channels)
5. Install the app to your workspace
6. Copy the **Bot User OAuth Token** (`xoxb-...`) and **App-Level Token** (`xapp-...`)

### 2. Configure

Add to `~/.encmind/config.yaml`:

```yaml
channels:
  slack:
    bot_token_env: "SLACK_BOT_TOKEN"
    app_token_env: "SLACK_APP_TOKEN"
  access_policy:
    default_action: allow
```

Set the environment variables before starting the server:

```bash
export SLACK_BOT_TOKEN="xoxb-..."
export SLACK_APP_TOKEN="xapp-..."
```

The bot will appear online in Slack once the server starts. Send it a direct message to chat.

---

## Edge Device Permissions

When an edge device pairs with the server, it receives default permissions. By default only `chat` is enabled. To grant file and shell access so the assistant can operate files and run commands on the device, add to `~/.encmind/config.yaml`:

```yaml
gateway:
  default_device_permissions:
    chat: true
    file_read: true
    file_write: true
    file_list: true
    bash_exec: true
    admin: false
```

This applies to **newly paired** devices. If you set this before pairing, no further steps are needed.

If a device was already paired with the old defaults, you can update its permissions via the `nodes.update_permissions` admin API, or directly in the database:

```bash
sqlite3 ~/.encmind/data.db "UPDATE paired_devices SET permissions = json_set(
  permissions,
  '$.file_read', json('true'),
  '$.file_write', json('true'),
  '$.file_list', json('true'),
  '$.bash_exec', json('true')
) WHERE name = 'my-laptop';"
```

Once permissions are granted and an edge device is connected (`encmind-edge connect`), the assistant can use these tools from any channel (Slack, WebSocket, etc.):

| Tool | Description |
|---|---|
| `file_read` | Read a file on the device |
| `file_write` | Write content to a file |
| `file_list` | List a directory |
| `bash_exec` | Run a shell command (30s timeout) |

Each tool accepts an optional `device_id` parameter to target a specific device when multiple are connected.

---

## Security Configuration

Add to `~/.encmind/config.yaml`:

```yaml
security:
  bash_mode: ask
  egress_firewall:
    enabled: true
    mode: allow_public_internet
    global_allowlist: []
    block_private_ranges: true
  rate_limit:
    messages_per_minute: 30
    tool_calls_per_run: 50
```

Firewall modes:
- `deny_by_default` — blocks all outbound URLs not in `global_allowlist` (production default)
- `allow_public_internet` — allows all public domains, still blocks private/local IPs (recommended for development)

---

## NAT / Firewalled Networks

If inbound internet traffic is hard (CGNAT, strict firewall), use Tailscale.

```bash
# install and bring up tailscale on server + client
tailscale ip -4
# example output: 100.64.0.1

encmind-edge --gateway wss://100.64.0.1:8443 pair --name "laptop"
```

Use `./install.sh --profile remote` on the server for this path.

---

## System Service (Optional)

`install.sh` can install a service definition:
- Linux: `/etc/systemd/system/encmind.service` (when run with sufficient privileges)
- macOS: `~/Library/LaunchAgents/com.encmind.core.plist`

Installer flags:
- `--skip-service` to avoid installing service definitions
- `--skip-setup` to install artifacts only (defer `encmind-core setup`)
- `--skip-rust-build` to reuse existing Rust build outputs
- `--workspace-build` to compile the full workspace instead of only required binaries

Linux quick enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now encmind
sudo systemctl status encmind
```

Ensure the service has:
- `Environment=ENCMIND_PASSPHRASE=...`
- access to your LLM API key environment

---

## Directory Layout

```
~/.encmind/
  config.yaml
  data.db
  bin/
    encmind-core
    encmind-edge
  tls/                # auto-generated in remote profile
  logs/
  data/               # created by installer (reserved for data/backups)

~/.encmind-edge/
  identity.json
  known_hosts         # pinned TLS fingerprints
```

---

## Useful Commands

| Command | Purpose |
|---|---|
| `./install.sh --profile local` | Build/install and initialize local config/database |
| `./install.sh --profile remote` | Build/install and initialize remote mode (auto-TLS + pinned trust flow) |
| `./install.sh --profile domain --acme-domain ... --acme-email ...` | Build/install and initialize domain mode with ACME |
| `./install.sh --profile domain --tls-cert-path ... --tls-key-path ...` | Build/install and initialize domain mode with manual cert |
| `encmind-core setup ...` | Setup only (advanced/manual path, without reinstall) |
| `encmind-core serve` | Start server |
| `encmind-core status` | Show local status |
| `encmind-edge pair --name "<name>"` | Pair edge device |
| `encmind-edge connect` | Connect edge device |
| `encmind-edge status` | Show edge identity and gateway |

---

## Quick Troubleshooting

- `encmind-core` not found:
  - `export PATH="$HOME/.encmind/bin:$PATH"`
- TLS connect fails in remote mode:
  - verify server is running and port `8443` is open
  - retry pairing and accept/pin fingerprint prompt
- Domain mode fails:
  - confirm `--acme-domain/--acme-email` or manual cert paths are set
  - verify DNS and certificate files are valid


 Step 2: Test Offline Commands (no server needed)

 # These work without a running gateway:

 # status — shows "Not set up yet" if no identity file exists
 cargo run -p encmind-edge -- status

 # config — prints gateway URL and fingerprint settings
 cargo run -p encmind-edge -- config

 # discover — scans LAN for mDNS _encmind._tcp.local. (times out if none)
 cargo run -p encmind-edge -- discover --timeout 3


 Step 3: Pairing (requires running gateway)

 # Pair with the local gateway (generates ~/.encmind-edge/identity.json)
 cargo run -p encmind-edge -- --gateway ws://localhost:8443 pair --name "test-laptop"

 # Server logs will print a 6-digit pairing code — enter it when prompted.
 # On success: "Pairing successful! Device registered as: <device_id>"


 After pairing, re-run status to see the device ID and identity file path:

 cargo run -p encmind-edge -- --gateway ws://localhost:8443 status


 Step 4: Test Setup Wizard (alternative to manual pair)

 # Runs discover → pair in one step.
 # With --gateway: skips discovery, goes straight to pair.
 cargo run -p encmind-edge -- --gateway ws://localhost:8443 setup


 Step 5: Chat Commands (requires pairing done)

 # One-shot message
 cargo run -p encmind-edge -- --gateway ws://localhost:8443 -m "What is 2+2?"

 # Interactive REPL
 cargo run -p encmind-edge -- --gateway ws://localhost:8443 chat

 # Inside REPL, test slash commands:
 #   /help         — list available commands
 #   /new          — start new session
 #   /sessions     — list all sessions
 #   /session <ID> — switch to session
 #   /history      — show messages in current session
 #   /model gpt-4  — override model
 #   /model        — clear model override
 #   /status       — memory status
 #   /exit         — quit

 # Resume a session
 cargo run -p encmind-edge -- --gateway ws://localhost:8443 --session <SESSION_ID> chat


 Step 6: Session Management

 # List sessions
 cargo run -p encmind-edge -- --gateway ws://localhost:8443 sessions list

 # Rename a session
 cargo run -p encmind-edge -- --gateway ws://localhost:8443 sessions rename <ID> "My Test Chat"

 # Delete a session
 cargo run -p encmind-edge -- --gateway ws://localhost:8443 sessions delete <ID>


 Step 7: Memory Commands

 # Memory status
 cargo run -p encmind-edge -- --gateway ws://localhost:8443 memory status

 # Search memories (requires some chat history with memory enabled)
 cargo run -p encmind-edge -- --gateway ws://localhost:8443 memory search "test query"


 Step 8: Node Connect Mode

 # Listen for remote commands from the gateway
 cargo run -p encmind-edge -- --gateway ws://localhost:8443 connect

 # The gateway can now invoke file.read, file.write, file.list, bash.exec
 # on this client via the nodes.invoke RPC method.
 # Ctrl+C to disconnect.


 Step 8b: Testing Node Commands (bash.exec, file operations)

 Prerequisites:
 - The server is running (`encmind-core serve`)
 - An edge device is connected in another terminal:
     cargo run --bin encmind-edge -- connect
 - The device has file and bash permissions (see "Edge Device Permissions" above)

 Open a chat session in a second terminal:

 cargo run --bin encmind-edge -- chat

 # --- 1. bash.exec: run a shell command ---
 # In the REPL, ask:
 #   run `ls /tmp` on my device
 # Expected: agent calls bash_exec tool, returns directory listing

 # --- 2. file.write + file.read round-trip ---
 # In the REPL, ask:
 #   write "hello from encmind" to /tmp/encmind-test.txt on my device
 # Expected: agent calls file_write, confirms success
 # Then ask:
 #   read /tmp/encmind-test.txt on my device
 # Expected: returns "hello from encmind"

 # --- 3. Timeout (30s limit) ---
 # In the REPL, ask:
 #   run `sleep 60` on my device
 # Expected: after ~30 seconds, returns error:
 #   "command timed out after 30s"

 # --- 4. Output truncation (256KB per stream) ---
 # In the REPL, ask:
 #   run `yes | head -c 300000` on my device
 # Expected: output is truncated with notice:
 #   "[output truncated to 262144 bytes per stream]"

 # --- 5. Permission denied ---
 # Revoke bash_exec permission via admin RPC:
 #   /rpc nodes.update_permissions {"device_id": "<DEVICE_ID>", "permissions": {"admin": true, "bash_exec": false, "chat": true, "file_list": true, "file_read": true, "file_write": true}}
 # Then ask:
 #   run `whoami` on my device
 # Expected: error "bash.exec: not permitted on device '<name>'"
 #
 # Restore permissions:
 #   /rpc nodes.update_permissions {"device_id": "<DEVICE_ID>", "permissions": {"admin": true, "bash_exec": true, "chat": true, "file_list": true, "file_read": true, "file_write": true}}

 # --- 6. Automated unit tests (no server needed) ---
 cargo test -p encmind-edge commands
 # Runs 26 tests covering:
 #   - Policy allow/deny for each command type
 #   - File read/write/list execution
 #   - Bash echo, stderr capture, exit codes, output truncation
 #   - Denied paths (~/.ssh, etc.), allowed roots enforcement
 #   - Symlink traversal and dot-dot traversal blocking


 Step 9: TLS / Fingerprint Testing

 # Start gateway with auto-TLS (default for remote profile)
 # Gateway prints: "Fingerprint: SHA256:xx:yy:..."

 # Connect with explicit fingerprint
 cargo run -p encmind-edge -- \
   --gateway wss://localhost:8443 \
   --fingerprint "SHA256:xx:yy:..." \
   status

 # TOFU flow: connect without fingerprint to a TLS gateway
 # → prompts "Trust and pin this fingerprint? [y/N]"
 # → on "y", saves to ~/.encmind-edge/known_hosts
 cargo run -p encmind-edge -- --gateway wss://localhost:8443 chat -m "hello"


 Automated Test Verification

 # Unit tests (155 tests, no server needed)
 cargo test -p encmind-edge

 # Lint
 cargo clippy -p encmind-edge -- -D warnings


 Notes

 - Identity file: ~/.encmind-edge/identity.json — delete to reset pairing state
 - Known hosts: ~/.encmind-edge/known_hosts — delete to reset TOFU pins
 - Custom identity: use --identity /path/to/id.json to test multiple devices
 - No end-to-end integration tests exist yet; all 155 tests are unit-level
╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
