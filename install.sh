#!/usr/bin/env bash
set -euo pipefail

# EncMind — build & install script
# Builds the Rust binaries, then creates the runtime directory structure.

if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    TARGET_USER="${SUDO_USER}"
    TARGET_HOME="$(eval echo "~${SUDO_USER}")"
else
    TARGET_USER="$(id -un)"
    TARGET_HOME="${HOME}"
fi

if [ -n "${INSTALL_DIR:-}" ]; then
    INSTALL_DIR="${INSTALL_DIR}"
else
    INSTALL_DIR="${TARGET_HOME}/.encmind"
fi
BIN_DIR="${INSTALL_DIR}/bin"
DATA_DIR="${INSTALL_DIR}/data"
CONFIG_DIR="${INSTALL_DIR}"
LOG_DIR="${INSTALL_DIR}/logs"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

info()  { printf '\033[1;34m[INFO]\033[0m  %s\n' "$1"; }
warn()  { printf '\033[1;33m[WARN]\033[0m  %s\n' "$1"; }
error() { printf '\033[1;31m[ERROR]\033[0m %s\n' "$1"; exit 1; }

usage() {
    cat <<'EOF'
Usage: ./install.sh [options]

Options:
  --profile local|remote|domain   Setup profile to initialize (default: local)
  --acme-domain <domain>          ACME domain (requires --profile domain and --acme-email)
  --acme-email <email>            ACME email (requires --profile domain and --acme-domain)
  --tls-cert-path <path>          Manual TLS cert path (requires --profile domain and --tls-key-path)
  --tls-key-path <path>           Manual TLS key path (requires --profile domain and --tls-cert-path)
  --skip-setup                    Install artifacts only (skip `encmind-core setup`; profile/TLS flags ignored)
  --skip-service                  Skip system service/plist installation
  --skip-rust-build               Reuse existing Rust binaries from Cargo target dir (may be stale)
  --workspace-build               Build full Rust workspace (default builds only required binaries)
  -h, --help                      Show this help

Examples:
  ./install.sh --profile local
  ./install.sh --profile remote
  ./install.sh --profile domain --acme-domain assistant.example.com --acme-email ops@example.com
  ./install.sh --profile domain --tls-cert-path /etc/ssl/cert.pem --tls-key-path /etc/ssl/key.pem
EOF
}

PROFILE="local"
ACME_DOMAIN=""
ACME_EMAIL=""
TLS_CERT_PATH=""
TLS_KEY_PATH=""
SKIP_SETUP=0
SKIP_SERVICE=0
SKIP_RUST_BUILD=0
WORKSPACE_BUILD=0

if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    BUILD_TARGET_DIR="${CARGO_TARGET_DIR}"
elif [ -n "${CARGO_BUILD_TARGET_DIR:-}" ]; then
    BUILD_TARGET_DIR="${CARGO_BUILD_TARGET_DIR}"
else
    BUILD_TARGET_DIR="${SCRIPT_DIR}/target"
fi

if [[ "${BUILD_TARGET_DIR}" != /* ]]; then
    BUILD_TARGET_DIR="${SCRIPT_DIR}/${BUILD_TARGET_DIR}"
fi

require_value() {
    local flag="$1"
    local value="${2:-}"
    if [ -z "$value" ] || [[ "$value" == --* ]]; then
        error "$flag requires a value"
    fi
}

warn_if_artifact_stale() {
    local bin_path="$1"
    local bin_name="$2"

    # Best-effort freshness check: if any workspace source/config file is newer
    # than the reused binary, warn that --skip-rust-build may be stale.
    local newer_file=""
    newer_file="$(find \
        "$SCRIPT_DIR/Cargo.toml" \
        "$SCRIPT_DIR/Cargo.lock" \
        "$SCRIPT_DIR/crates" \
        -type f \
        -newer "$bin_path" \
        -print -quit 2>/dev/null || true)"
    if [ -n "$newer_file" ]; then
        warn "${bin_name} artifact appears stale (${bin_path} older than ${newer_file})."
        warn "Rerun without --skip-rust-build to rebuild."
    fi
}

find_workspace_source_newer_than() {
    local bin_path="$1"
    find \
        "$SCRIPT_DIR/Cargo.toml" \
        "$SCRIPT_DIR/Cargo.lock" \
        "$SCRIPT_DIR/crates" \
        -type f \
        \( -name "*.rs" -o -name "Cargo.toml" \) \
        -newer "$bin_path" \
        -print -quit 2>/dev/null || true
}

while [ $# -gt 0 ]; do
    case "$1" in
        --profile)
            require_value "$1" "${2:-}"
            PROFILE="$2"
            shift 2
            ;;
        --acme-domain)
            require_value "$1" "${2:-}"
            ACME_DOMAIN="$2"
            shift 2
            ;;
        --acme-email)
            require_value "$1" "${2:-}"
            ACME_EMAIL="$2"
            shift 2
            ;;
        --tls-cert-path)
            require_value "$1" "${2:-}"
            TLS_CERT_PATH="$2"
            shift 2
            ;;
        --tls-key-path)
            require_value "$1" "${2:-}"
            TLS_KEY_PATH="$2"
            shift 2
            ;;
        --skip-setup)
            SKIP_SETUP=1
            shift
            ;;
        --skip-service)
            SKIP_SERVICE=1
            shift
            ;;
        --skip-rust-build)
            SKIP_RUST_BUILD=1
            shift
            ;;
        --workspace-build)
            WORKSPACE_BUILD=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            error "Unknown option: $1 (use --help)"
            ;;
    esac
done

case "$PROFILE" in
    local|remote|domain) ;;
    *)
        error "Invalid profile '$PROFILE' (expected: local, remote, domain)"
        ;;
esac

HAS_ACME=0
HAS_MANUAL_TLS=0
if [ -n "$ACME_DOMAIN" ] || [ -n "$ACME_EMAIL" ]; then
    HAS_ACME=1
fi
if [ -n "$TLS_CERT_PATH" ] || [ -n "$TLS_KEY_PATH" ]; then
    HAS_MANUAL_TLS=1
fi

if [ "$SKIP_SETUP" -eq 1 ]; then
    if [ "$PROFILE" != "local" ] || [ "$HAS_ACME" -eq 1 ] || [ "$HAS_MANUAL_TLS" -eq 1 ]; then
        warn "--skip-setup set: setup-related flags are ignored"
    fi
else
    if [ "$HAS_ACME" -eq 1 ] && { [ -z "$ACME_DOMAIN" ] || [ -z "$ACME_EMAIL" ]; }; then
        error "Both --acme-domain and --acme-email are required together"
    fi

    if [ "$HAS_MANUAL_TLS" -eq 1 ] && { [ -z "$TLS_CERT_PATH" ] || [ -z "$TLS_KEY_PATH" ]; }; then
        error "Both --tls-cert-path and --tls-key-path are required together"
    fi

    if [ "$HAS_ACME" -eq 1 ] && [ "$HAS_MANUAL_TLS" -eq 1 ]; then
        error "ACME options and manual TLS options are mutually exclusive"
    fi

    if [ "$PROFILE" != "domain" ] && { [ "$HAS_ACME" -eq 1 ] || [ "$HAS_MANUAL_TLS" -eq 1 ]; }; then
        error "--acme-* and --tls-*-path options are only valid with --profile domain"
    fi

    if [ "$PROFILE" = "domain" ] && [ "$HAS_ACME" -eq 0 ] && [ "$HAS_MANUAL_TLS" -eq 0 ]; then
        error "profile=domain requires ACME (--acme-domain + --acme-email) or manual TLS (--tls-cert-path + --tls-key-path)"
    fi
fi

# ---------- pre-flight checks ----------

if [ "$SKIP_RUST_BUILD" -eq 0 ]; then
    command -v cargo >/dev/null 2>&1 || error "cargo not found — install Rust via https://rustup.rs"
fi
info "Detected OS: $(uname -s) / Arch: $(uname -m)"
info "Using Rust target dir: ${BUILD_TARGET_DIR}"

# ---------- build Rust workspace ----------

cd "$SCRIPT_DIR"
if [ "$SKIP_RUST_BUILD" -eq 1 ]; then
    warn "Skipping Rust build (--skip-rust-build): reusing existing artifacts from ${BUILD_TARGET_DIR}/release (may be stale)."
else
    GIT_HASH="$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    info "Building from git commit: ${GIT_HASH}"

    run_rust_build() {
        # Disable incremental compilation for release builds to prevent stale
        # cached artifacts from being linked in (e.g., a dependency crate's
        # source changes not being detected by the incremental cache).
        export CARGO_INCREMENTAL=0

        # Force-clean the final binary crates so they are always relinked from
        # scratch. This ensures cargo re-checks all dependency artifacts and
        # prevents stale intermediate objects from being linked in.
        info "Cleaning binary crates to prevent stale linkage..."
        cargo clean --release -p encmind-cli -p encmind-edge 2>/dev/null || true

        if [ "$WORKSPACE_BUILD" -eq 1 ]; then
            info "Building full Rust workspace (release, incremental=off)..."
            cargo build --release --workspace --target-dir "$BUILD_TARGET_DIR" 2>&1
        else
            info "Building required Rust binaries only (release, incremental=off)..."
            cargo build --release -p encmind-cli -p encmind-edge --target-dir "$BUILD_TARGET_DIR" 2>&1
        fi
    }

    run_rust_build
fi

CLI_BIN="${BUILD_TARGET_DIR}/release/encmind-core"
BRIDGE_BIN="${BUILD_TARGET_DIR}/release/encmind-edge"

[ -f "$CLI_BIN" ]    || error "encmind-core binary not found after build"
[ -f "$BRIDGE_BIN" ] || error "encmind-edge binary not found after build"

if [ "$SKIP_RUST_BUILD" -eq 0 ]; then
    stale_core="$(find_workspace_source_newer_than "$CLI_BIN")"
    if [ -n "$stale_core" ]; then
        warn "Detected source files newer than encmind-core (possible stale build cache)."
        [ -n "$stale_core" ] && warn "  encmind-core older than: $stale_core"
        warn "Running clean rebuild once..."
        cargo clean --target-dir "$BUILD_TARGET_DIR" 2>&1
        run_rust_build
        stale_core="$(find_workspace_source_newer_than "$CLI_BIN")"
        if [ -n "$stale_core" ]; then
            error "encmind-core binary still older than source after clean rebuild: $stale_core"
        fi
    fi
else
    warn_if_artifact_stale "$CLI_BIN" "encmind-core"
fi

# ---------- create directory structure ----------

info "Creating directory structure at $INSTALL_DIR ..."
mkdir -p "$BIN_DIR" "$DATA_DIR" "$CONFIG_DIR" "$LOG_DIR"

# ---------- copy artefacts ----------

info "Installing binaries..."
cp "$CLI_BIN"    "$BIN_DIR/encmind-core"
cp "$BRIDGE_BIN" "$BIN_DIR/encmind-edge"
chmod +x "$BIN_DIR/encmind-core" "$BIN_DIR/encmind-edge"
# Install integrity check only (copy success / corruption guard), not freshness.
cmp -s "$CLI_BIN" "$BIN_DIR/encmind-core" || error "encmind-core install verification failed"
cmp -s "$BRIDGE_BIN" "$BIN_DIR/encmind-edge" || error "encmind-edge install verification failed"
core_version="$("$BIN_DIR/encmind-core" --version 2>/dev/null || true)"
[ -n "$core_version" ] || error "installed encmind-core failed to execute (--version)"
"$BIN_DIR/encmind-edge" --help >/dev/null 2>&1 || error "installed encmind-edge failed to execute (--help)"
info "Installed core version: ${core_version}"
info "Installed edge binary smoke check: ok"

# ---------- initialize config + database ----------

CONFIG_FILE="$CONFIG_DIR/config.yaml"
if [ "$SKIP_SETUP" -eq 1 ]; then
    warn "Skipping setup. Run this manually when ready:"
    warn "  $BIN_DIR/encmind-core --config $CONFIG_FILE setup --profile $PROFILE"
else
    setup_args=(setup --profile "$PROFILE")
    if [ -n "$ACME_DOMAIN" ]; then
        setup_args+=(--acme-domain "$ACME_DOMAIN" --acme-email "$ACME_EMAIL")
    fi
    if [ -n "$TLS_CERT_PATH" ]; then
        setup_args+=(--tls-cert-path "$TLS_CERT_PATH" --tls-key-path "$TLS_KEY_PATH")
    fi

    info "Initializing config/database via encmind-core setup (profile=$PROFILE)..."
    "$BIN_DIR/encmind-core" --config "$CONFIG_FILE" "${setup_args[@]}"
fi

# ---------- install system service ----------

install_systemd_service() {
    local SERVICE_FILE="/etc/systemd/system/encmind.service"

    if [ -f "$SERVICE_FILE" ]; then
        info "systemd service already exists at $SERVICE_FILE — skipping."
        return
    fi

    if [ "$(id -u)" -ne 0 ]; then
        warn "Not running as root — skipping systemd service installation."
        warn "To install the service manually, run:"
        warn "  sudo $0"
        warn "Or create $SERVICE_FILE yourself."
        return
    fi

    local RUN_USER="${TARGET_USER}"
    info "Creating systemd service at $SERVICE_FILE ..."
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=EncMind Core Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
ExecStart=${BIN_DIR}/encmind-core --config ${CONFIG_FILE} serve
Restart=on-failure
RestartSec=5
Environment=ENCMIND_PASSPHRASE=
WorkingDirectory=${INSTALL_DIR}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    info "systemd service installed. To start:"
    info "  1. Set ENCMIND_PASSPHRASE in $SERVICE_FILE under [Service] Environment="
    info "  2. sudo systemctl enable --now encmind"
}

install_launchd_plist() {
    local PLIST_DIR="$TARGET_HOME/Library/LaunchAgents"
    local PLIST_FILE="$PLIST_DIR/com.encmind.core.plist"

    if [ -f "$PLIST_FILE" ]; then
        info "launchd plist already exists at $PLIST_FILE — skipping."
        return
    fi

    mkdir -p "$PLIST_DIR"

    info "Creating launchd plist at $PLIST_FILE ..."
    cat > "$PLIST_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.encmind.core</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN_DIR}/encmind-core</string>
        <string>--config</string>
        <string>${CONFIG_FILE}</string>
        <string>serve</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>EnvironmentVariables</key>
    <dict>
        <key>ENCMIND_PASSPHRASE</key>
        <string></string>
    </dict>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/encmind-core.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/encmind-core.err</string>
    <key>WorkingDirectory</key>
    <string>${TARGET_HOME}</string>
</dict>
</plist>
EOF

    if [ "$(id -u)" -eq 0 ] && [ "$TARGET_USER" != "root" ]; then
        chown "$TARGET_USER" "$PLIST_FILE" || warn "failed to chown $PLIST_FILE to $TARGET_USER"
    fi

    info "launchd plist installed. To start:"
    info "  1. Set ENCMIND_PASSPHRASE in $PLIST_FILE"
    info "  2. launchctl load $PLIST_FILE"
    info "  3. launchctl start com.encmind.core"
}

if [ "$SKIP_SERVICE" -eq 1 ]; then
    info "Skipping system service installation (--skip-service)."
else
    OS="$(uname -s)"
    case "$OS" in
        Linux)
            if command -v systemctl >/dev/null 2>&1; then
                install_systemd_service
            else
                warn "systemctl not found — skipping service installation."
            fi
            ;;
        Darwin)
            install_launchd_plist
            ;;
        *)
            warn "Unknown OS '$OS' — skipping service installation."
            ;;
    esac
fi

# ---------- PATH hint ----------

if ! echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
    warn "Add the following to your shell profile:"
    warn "  export PATH=\"$BIN_DIR:\$PATH\""
fi

expected_core="$BIN_DIR/encmind-core"
expected_edge="$BIN_DIR/encmind-edge"
resolved_core="$(type -P encmind-core 2>/dev/null || true)"
resolved_edge="$(type -P encmind-edge 2>/dev/null || true)"
if [ -n "$resolved_core" ] && [ "$resolved_core" != "$expected_core" ]; then
    warn "PATH shadowing detected: 'encmind-core' resolves to '$resolved_core' (expected '$expected_core')."
    warn "Use the absolute path: $expected_core --config $CONFIG_FILE serve"
    warn "If your shell cached the old location, run: hash -r"
fi
if [ -n "$resolved_edge" ] && [ "$resolved_edge" != "$expected_edge" ]; then
    warn "PATH shadowing detected: 'encmind-edge' resolves to '$resolved_edge' (expected '$expected_edge')."
    warn "Use the absolute path: $expected_edge --gateway ws://localhost:8443 pair"
    warn "If your shell cached the old location, run: hash -r"
fi

info "Installation complete!"
info "  Binaries:  $BIN_DIR/encmind-core, $BIN_DIR/encmind-edge"
info "  Config:    $CONFIG_FILE"
info "  Data:      $DATA_DIR/"
info ""
info "Start the server with:  $BIN_DIR/encmind-core --config $CONFIG_FILE serve"
info "If your shell still runs an old binary, run: hash -r"
