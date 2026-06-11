#!/usr/bin/env bash
set -Eeuo pipefail

# ==============================================================================
# install-vaultwarden.sh
#
# Vaultwarden + Caddy + Docker Compose installer for Debian/Ubuntu
#
# Recommended operational model:
#   - SIGNUPS_ALLOWED=false
#   - INVITATIONS_ALLOWED=true
#
# Meaning:
#   - public self-registration is disabled
#   - new users can be added only by admin invite
#   - no separate "open/close invitation window" maintenance script is needed
#
# Features:
#   - Docker Engine + Docker Compose plugin
#   - Vaultwarden container
#   - Caddy reverse proxy with automatic HTTPS / Let's Encrypt
#   - Argon2id ADMIN_TOKEN generated locally via python3-argon2
#   - Optional Caddy Basic Auth for /admin with dedicated realm
#   - Optional IP/CIDR allowlist for /admin
#   - Backup / restore scripts
#   - Optional systemd backup timer
#   - Optional UFW local firewall
#   - Fail2ban with DOCKER-USER chain for Docker traffic
#   - CrowdSec + firewall-bouncer
#   - CrowdSec Docker enforcement:
#       cscli decisions -> ipset crowdsec-blacklists -> DOCKER-USER DROP
#   - Docker log rotation
#   - SMTP provider presets:
#       GMAIL   -> smtp.gmail.com:587 starttls
#       SMTP2GO -> mail.smtp2go.com:2525 starttls
#       BREVO   -> smtp-relay.brevo.com:2525 starttls
#       CUSTOM
#   - User-friendly colored prompts and explanation blocks
#
# Run:
#   sudo bash install-vaultwarden.sh
# ==============================================================================

APP_DIR="/opt/vaultwarden"
BACKUP_DIR="/opt/vaultwarden-backups"

DATA_DIR=""
COMPOSE_FILE=""
ENV_FILE=""
CADDYFILE=""

OS_ID=""
OS_CODENAME=""

DOMAIN_NAME=""
ACME_EMAIL=""

# Change this to "yes" if you want SMTP enabled by default.
SMTP_ENABLE="no"
SMTP_SERVICE="GMAIL"
SMTP_HOST=""
SMTP_PORT=""
SMTP_SECURITY=""
SMTP_FROM=""
SMTP_USERNAME=""
SMTP_PASSWORD=""

SIGNUPS_ALLOWED="false"
INVITATIONS_ALLOWED="true"

ADMIN_TOKEN_HASH=""

ADMIN_BASIC_AUTH_ENABLE="yes"
ADMIN_BASIC_USER=""
ADMIN_BASIC_HASH=""
ADMIN_BASIC_REALM="Vaultwarden Admin Area"

ADMIN_ALLOWED_IPS=""

PROTECTION_MODE="both"
UFW_ENABLE="yes"

BACKUP_TIMER_ENABLE="yes"
BACKUP_TIME="03:30"

# ==============================================================================
# UI helpers
# ==============================================================================

if [[ -t 1 ]]; then
  C_RESET="\033[0m"
  C_BOLD="\033[1m"
  C_DIM="\033[2m"
  C_RED="\033[31m"
  C_GREEN="\033[32m"
  C_YELLOW="\033[33m"
  C_BLUE="\033[34m"
  C_MAGENTA="\033[35m"
  C_CYAN="\033[36m"
else
  C_RESET=""
  C_BOLD=""
  C_DIM=""
  C_RED=""
  C_GREEN=""
  C_YELLOW=""
  C_BLUE=""
  C_MAGENTA=""
  C_CYAN=""
fi

section_title() {
  echo
  echo -e "${C_BOLD}${C_CYAN}================================================================================${C_RESET}"
  echo -e "${C_BOLD}${C_CYAN}$*${C_RESET}"
  echo -e "${C_BOLD}${C_CYAN}================================================================================${C_RESET}"
}

info_block() {
  local title="$1"
  local body="$2"

  echo
  echo -e "${C_BOLD}${C_BLUE}┌─ ${title}${C_RESET}"
  while IFS= read -r line; do
    echo -e "${C_BLUE}│${C_RESET} ${C_DIM}${line}${C_RESET}"
  done <<< "${body}"
  echo -e "${C_BOLD}${C_BLUE}└──────────────────────────────────────────────────────────────────────────────${C_RESET}"
}

option_prompt() {
  local var_name="$1"
  local question="$2"
  local default="${3:-}"
  local value=""

  echo
  echo -e "${C_BOLD}${C_YELLOW}▶ ${question}${C_RESET}"

  if [[ -n "${default}" ]]; then
    echo -e "${C_DIM}  Default: ${default}${C_RESET}"
    read -r -p "  Enter value [${default}]: " value
    value="${value:-$default}"
  else
    read -r -p "  Enter value: " value
  fi

  printf -v "${var_name}" '%s' "${value}"
}

option_secret() {
  local var_name="$1"
  local question="$2"
  local value=""

  echo
  echo -e "${C_BOLD}${C_YELLOW}▶ ${question}${C_RESET}"
  read -r -s -p "  Enter secret value: " value
  echo

  [[ -n "${value}" ]] || die "Empty value is not allowed."

  printf -v "${var_name}" '%s' "${value}"
}

die() {
  echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2
  exit 1
}

info() {
  echo -e "${C_GREEN}[INFO]${C_RESET} $*" >&2
}

warn() {
  echo -e "${C_YELLOW}[WARN]${C_RESET} $*" >&2
}

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run this script as root."
}

detect_os() {
  [[ -r /etc/os-release ]] || die "/etc/os-release not found."

  # shellcheck disable=SC1091
  . /etc/os-release

  case "${ID}" in
    ubuntu|debian)
      OS_ID="${ID}"
      OS_CODENAME="${VERSION_CODENAME:-}"
      ;;
    *)
      die "Unsupported OS: ${ID}. Use Debian or Ubuntu."
      ;;
  esac

  [[ -n "${OS_CODENAME}" ]] || die "Could not detect OS codename."
}

normalize_yes_no() {
  local value="${1,,}"

  case "${value}" in
    y|yes|true|1)
      echo "yes"
      ;;
    n|no|false|0)
      echo "no"
      ;;
    *)
      die "Invalid yes/no value: ${1}"
      ;;
  esac
}

validate_true_false() {
  local value="${1,,}"

  case "${value}" in
    true|false)
      echo "${value}"
      ;;
    yes|y|1)
      echo "true"
      ;;
    no|n|0)
      echo "false"
      ;;
    *)
      die "Invalid true/false value: ${1}"
      ;;
  esac
}

normalize_smtp_service() {
  local value="${1,,}"

  case "${value}" in
    1|gmail|google)
      echo "GMAIL"
      ;;
    2|smtp2go|smtp-2-go|smtp_to_go)
      echo "SMTP2GO"
      ;;
    3|brevo|sendinblue)
      echo "BREVO"
      ;;
    4|custom|manual)
      echo "CUSTOM"
      ;;
    *)
      die "Invalid SMTP service: ${1}"
      ;;
  esac
}

env_single_quote() {
  local value="$1"

  # Docker Compose .env supports single-quoted values.
  # This prevents $argon2id and passwords with $ from being interpolated.
  value="${value//\'/\\\'}"

  printf "'%s'" "${value}"
}

install_base_packages() {
  info "Installing base packages..."

  apt-get update

  apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    openssl \
    apache2-utils \
    sqlite3 \
    jq \
    tar \
    rsync \
    cron \
    systemd \
    python3 \
    python3-argon2 \
    iptables \
    ipset \
    netcat-openbsd
}

install_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    info "Docker and Docker Compose plugin already installed."
    systemctl enable --now docker
    return
  fi

  info "Installing Docker Engine from official Docker APT repository..."

  apt-get remove -y docker docker-engine docker.io containerd runc podman-docker || true

  install -m 0755 -d /etc/apt/keyrings
  rm -f /etc/apt/keyrings/docker.gpg

  curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

  chmod a+r /etc/apt/keyrings/docker.gpg

  local arch
  arch="$(dpkg --print-architecture)"

  cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${OS_ID} ${OS_CODENAME} stable
EOF

  apt-get update

  apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

  systemctl enable --now docker

  docker version >/dev/null
  docker compose version >/dev/null
}

configure_docker_log_rotation() {
  info "Configuring Docker log rotation..."

  mkdir -p /etc/docker

  if [[ -f /etc/docker/daemon.json ]]; then
    cp /etc/docker/daemon.json "/etc/docker/daemon.json.backup.$(date +%Y%m%d-%H%M%S)"
    warn "Existing /etc/docker/daemon.json backed up."
  fi

  cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "20m",
    "max-file": "5"
  }
}
EOF

  systemctl restart docker
}

generate_admin_token_hash() {
  local plain="$1"
  local hash=""

  info "Generating Vaultwarden Argon2id PHC ADMIN_TOKEN locally..."

  hash="$(
    ADMIN_PASSWORD_FOR_HASH="${plain}" python3 - <<'PY'
import os
import sys

try:
    from argon2 import PasswordHasher
    from argon2.low_level import Type
except Exception as e:
    print(f"python3-argon2 is missing or broken: {e}", file=sys.stderr)
    sys.exit(1)

password = os.environ.get("ADMIN_PASSWORD_FOR_HASH", "")

if not password:
    print("Empty admin password.", file=sys.stderr)
    sys.exit(1)

ph = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

print(ph.hash(password))
PY
  )"

  hash="$(printf '%s\n' "${hash}" | grep -E '^\$argon2id\$' | tail -n 1 || true)"

  [[ -n "${hash}" ]] || die "Could not generate ADMIN_TOKEN hash."

  printf '%s\n' "${hash}"
}

generate_caddy_basic_hash() {
  local plain="$1"
  local hash=""

  info "Generating Caddy Basic Auth hash..."

  hash="$(
    docker run --rm caddy:2 \
      caddy hash-password --plaintext "${plain}" 2>/dev/null || true
  )"

  [[ -n "${hash}" ]] || die "Could not generate Caddy Basic Auth hash."

  printf '%s\n' "${hash}"
}

collect_inputs() {
  section_title "Vaultwarden installation parameters"

  info_block "Domain name" \
"Enter the public domain that will be used to access Vaultwarden.

Example:
  vault.example.com

Important:
  - DNS A record must point to this VM.
  - If using Cloudflare, keep the record as DNS only, not proxied.
  - Caddy will request Let's Encrypt certificates for this domain."

  option_prompt DOMAIN_NAME "Vaultwarden domain" ""
  [[ "${DOMAIN_NAME}" =~ ^[a-zA-Z0-9.-]+$ ]] || die "Invalid domain."

  info_block "Let's Encrypt email" \
"This email is used by Let's Encrypt for certificate expiration and account notices.

It does not need to be the same email as your Vaultwarden user account."

  option_prompt ACME_EMAIL "Email for Let's Encrypt notifications" ""
  [[ "${ACME_EMAIL}" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "Invalid email."

  info_block "Install directory" \
"Vaultwarden files will be stored here.

Default:
  /opt/vaultwarden

This directory will contain:
  - docker-compose.yml
  - .env
  - Caddyfile
  - data directory with the SQLite database"

  option_prompt APP_DIR "Install directory" "${APP_DIR}"

  DATA_DIR="${APP_DIR}/data"
  COMPOSE_FILE="${APP_DIR}/docker-compose.yml"
  ENV_FILE="${APP_DIR}/.env"
  CADDYFILE="${APP_DIR}/Caddyfile"

  info_block "Backup directory" \
"Local backup archives will be stored here.

Important:
  Local backups are useful but not enough.
  You should later copy encrypted backups to off-server storage."

  option_prompt BACKUP_DIR "Backup directory" "${BACKUP_DIR}"

  info_block "SMTP configuration" \
"SMTP is recommended for Vaultwarden.

Needed for:
  - invitations
  - email verification
  - password reset
  - notifications

Current default:
  ${SMTP_ENABLE}

Available presets:
  1. GMAIL
     Host: smtp.gmail.com
     Port: 587
     Security: starttls

  2. SMTP2GO
     Host: mail.smtp2go.com
     Port: 2525
     Security: starttls

  3. BREVO
     Host: smtp-relay.brevo.com
     Port: 2525
     Security: starttls

  4. CUSTOM

Notes:
  - GMAIL requires Google App Password, not your normal Gmail password.
  - SMTP2GO requires an SMTP user/password from SMTP2GO.
  - BREVO requires an activated transactional SMTP account.
  - Many VPS providers block 25/465/587 outbound SMTP ports.
  - SMTP2GO/BREVO with 2525/starttls are usually better for VPS providers."

  option_prompt SMTP_ENABLE "Configure SMTP now? yes/no" "${SMTP_ENABLE}"
  SMTP_ENABLE="$(normalize_yes_no "${SMTP_ENABLE}")"

  if [[ "${SMTP_ENABLE}" == "yes" ]]; then
    info_block "SMTP service preset" \
"Choose the SMTP provider preset.

Default:
  1 / GMAIL

Options:
  1  GMAIL
  2  SMTP2GO
  3  BREVO
  4  CUSTOM

The preset only fills host, port and TLS mode.
You still need to enter sender address, username and password manually."

    option_prompt SMTP_SERVICE "Choose SMTP service: 1=GMAIL, 2=SMTP2GO, 3=BREVO, 4=CUSTOM" "GMAIL"
    SMTP_SERVICE="$(normalize_smtp_service "${SMTP_SERVICE}")"

    case "${SMTP_SERVICE}" in
      GMAIL)
        SMTP_HOST="smtp.gmail.com"
        SMTP_PORT="587"
        SMTP_SECURITY="starttls"

        info_block "GMAIL SMTP selected" \
"GMAIL defaults will be used:

  SMTP_HOST=smtp.gmail.com
  SMTP_PORT=587
  SMTP_SECURITY=starttls

Important:
  - Use a Google App Password.
  - Do not use your normal Gmail account password.
  - On many VPS providers, port 587 may be blocked.
  - If port 587 is blocked, GMAIL SMTP will not work from this VM."
        ;;
      SMTP2GO)
        SMTP_HOST="mail.smtp2go.com"
        SMTP_PORT="2525"
        SMTP_SECURITY="starttls"

        info_block "SMTP2GO SMTP selected" \
"SMTP2GO defaults will be used:

  SMTP_HOST=mail.smtp2go.com
  SMTP_PORT=2525
  SMTP_SECURITY=starttls

Required credentials:
  - SMTP_USERNAME = SMTP2GO SMTP username
  - SMTP_PASSWORD = SMTP2GO SMTP password

Your sender domain or sender address must be verified in SMTP2GO."
        ;;
      BREVO)
        SMTP_HOST="smtp-relay.brevo.com"
        SMTP_PORT="2525"
        SMTP_SECURITY="starttls"

        info_block "BREVO SMTP selected" \
"BREVO defaults will be used:

  SMTP_HOST=smtp-relay.brevo.com
  SMTP_PORT=2525
  SMTP_SECURITY=starttls

Required credentials:
  - SMTP_USERNAME = BREVO SMTP login
  - SMTP_PASSWORD = BREVO SMTP key

Your sender domain or sender address must be verified in BREVO.

Note:
  BREVO commonly documents port 587, but this preset uses 2525/starttls
  because it is often more convenient on VPS providers where standard SMTP
  ports may be blocked."
        ;;
      CUSTOM)
        info_block "CUSTOM SMTP selected" \
"Use this option if your SMTP provider is not GMAIL, SMTP2GO or BREVO.

You will enter:
  - SMTP host
  - SMTP port
  - SMTP security mode
  - SMTP from address
  - SMTP username
  - SMTP password"

        option_prompt SMTP_HOST "SMTP host" ""
        option_prompt SMTP_PORT "SMTP port" "587"
        option_prompt SMTP_SECURITY "SMTP security: starttls/force_tls/off" "starttls"

        case "${SMTP_SECURITY}" in
          starttls|force_tls|off) ;;
          *) die "Invalid SMTP_SECURITY. Use starttls, force_tls or off." ;;
        esac
        ;;
    esac

    if [[ "${SMTP_SERVICE}" != "CUSTOM" ]]; then
      info_block "SMTP preset values" \
"The selected preset produced these values:

  SMTP_HOST=${SMTP_HOST}
  SMTP_PORT=${SMTP_PORT}
  SMTP_SECURITY=${SMTP_SECURITY}

You can override them now if needed.
Press Enter to keep the default values."

      option_prompt SMTP_HOST "SMTP host" "${SMTP_HOST}"
      option_prompt SMTP_PORT "SMTP port" "${SMTP_PORT}"
      option_prompt SMTP_SECURITY "SMTP security: starttls/force_tls/off" "${SMTP_SECURITY}"

      case "${SMTP_SECURITY}" in
        starttls|force_tls|off) ;;
        *) die "Invalid SMTP_SECURITY. Use starttls, force_tls or off." ;;
      esac
    fi

    info_block "SMTP from address" \
"This is the sender address used by Vaultwarden.

Examples:
  vaultwarden@example.com
  yourname+vaultwarden@gmail.com

Provider-specific notes:
  - GMAIL: usually your Gmail address or plus-alias.
  - SMTP2GO/BREVO: use an address on a verified sender domain.

This address should be allowed by your SMTP provider."

    option_prompt SMTP_FROM "SMTP from address" ""

    case "${SMTP_SERVICE}" in
      GMAIL)
        info_block "GMAIL SMTP username" \
"For GMAIL, this is your real Gmail address.

Example:
  yourname@gmail.com

If SMTP_FROM uses a plus-alias like:
  yourname+vaultwarden@gmail.com

SMTP_USERNAME should still usually be:
  yourname@gmail.com"

        option_prompt SMTP_USERNAME "GMAIL SMTP username" ""
        ;;
      SMTP2GO)
        info_block "SMTP2GO SMTP username" \
"For SMTP2GO, use your SMTP2GO SMTP username.

Find it in:
  SMTP2GO Dashboard
    Sending
      SMTP Users

Do not use your normal account password unless SMTP2GO explicitly created it as an SMTP credential."

        option_prompt SMTP_USERNAME "SMTP2GO SMTP username" ""
        ;;
      BREVO)
        info_block "BREVO SMTP username" \
"For BREVO, use your BREVO SMTP login.

Find it in:
  BREVO Dashboard
    SMTP & API
      SMTP"

        option_prompt SMTP_USERNAME "BREVO SMTP login" ""
        ;;
      CUSTOM)
        info_block "SMTP username" \
"Enter the SMTP username from your SMTP provider.

This may be:
  - email address
  - API key
  - generated SMTP login
  - service-specific username"

        option_prompt SMTP_USERNAME "SMTP username" ""
        ;;
    esac

    case "${SMTP_SERVICE}" in
      GMAIL)
        info_block "GMAIL SMTP password" \
"For GMAIL, use a Google App Password.

Do not use your normal Gmail password.

Requirements:
  - 2-Step Verification enabled on the Google account
  - App Password generated for Vaultwarden/SMTP

This value will be stored in:
  ${ENV_FILE}

The script sets chmod 600 on the .env file."

        option_secret SMTP_PASSWORD "GMAIL App Password"
        ;;
      SMTP2GO)
        info_block "SMTP2GO SMTP password" \
"For SMTP2GO, use your SMTP2GO SMTP password.

Find it in:
  SMTP2GO Dashboard
    Sending
      SMTP Users

This value will be stored in:
  ${ENV_FILE}

The script sets chmod 600 on the .env file."

        option_secret SMTP_PASSWORD "SMTP2GO SMTP password"
        ;;
      BREVO)
        info_block "BREVO SMTP password" \
"For BREVO, use your BREVO SMTP key.

Find it in:
  BREVO Dashboard
    SMTP & API
      SMTP

This value will be stored in:
  ${ENV_FILE}

The script sets chmod 600 on the .env file."

        option_secret SMTP_PASSWORD "BREVO SMTP key"
        ;;
      CUSTOM)
        info_block "SMTP password" \
"Enter the SMTP password or SMTP API key from your provider.

This value will be stored in:
  ${ENV_FILE}

The script sets chmod 600 on the .env file."

        option_secret SMTP_PASSWORD "SMTP password"
        ;;
    esac
  fi

  info_block "Public registration" \
"Controls whether anyone can create an account without an invitation.

Recommended:
  false

For this setup, keep public registration disabled.
New users should be added by admin invite only."

  option_prompt SIGNUPS_ALLOWED "Allow open registration? true/false" "false"
  SIGNUPS_ALLOWED="$(validate_true_false "${SIGNUPS_ALLOWED}")"

  info_block "Invitations" \
"Controls whether users can be invited.

Recommended:
  true

With:
  SIGNUPS_ALLOWED=false
  INVITATIONS_ALLOWED=true

there is no public registration, but the admin can still invite new users from /admin."

  option_prompt INVITATIONS_ALLOWED "Allow admin/user invitations? true/false" "true"
  INVITATIONS_ALLOWED="$(validate_true_false "${INVITATIONS_ALLOWED}")"

  info_block "Vaultwarden admin password" \
"This password protects the Vaultwarden /admin panel.

The script does not store it in plaintext.
It generates an Argon2id ADMIN_TOKEN hash and writes only the hash to .env.

You will need this password to log into:
  https://${DOMAIN_NAME}/admin"

  local admin_password
  option_secret admin_password "Vaultwarden /admin password"

  ADMIN_TOKEN_HASH="$(generate_admin_token_hash "${admin_password}")"
  unset admin_password

  info_block "Extra Caddy Basic Auth for /admin" \
"This adds a second protection layer before the Vaultwarden admin token.

Access flow:
  1. Caddy Basic Auth
  2. Vaultwarden ADMIN_TOKEN

Recommended:
  yes

The script uses a dedicated Basic Auth realm:
  Vaultwarden Admin Area"

  option_prompt ADMIN_BASIC_AUTH_ENABLE "Add extra Caddy Basic Auth on /admin? yes/no" "yes"
  ADMIN_BASIC_AUTH_ENABLE="$(normalize_yes_no "${ADMIN_BASIC_AUTH_ENABLE}")"

  if [[ "${ADMIN_BASIC_AUTH_ENABLE}" == "yes" ]]; then
    info_block "Caddy Basic Auth username" \
"This is the username for the first /admin protection layer.

Default:
  vwadmin"

    option_prompt ADMIN_BASIC_USER "Caddy /admin Basic Auth username" "vwadmin"

    info_block "Caddy Basic Auth password" \
"This is separate from the Vaultwarden admin password.

You will enter:
  - Caddy username/password first
  - then Vaultwarden admin password

Use a strong unique password."

    local basic_password
    option_secret basic_password "Caddy /admin Basic Auth password"

    ADMIN_BASIC_HASH="$(generate_caddy_basic_hash "${basic_password}")"
    unset basic_password
  fi

  info_block "Admin IP allowlist" \
"Optional extra restriction for /admin.

Examples:
  203.0.113.10
  203.0.113.0/24
  10.0.0.0/8

Leave empty if:
  - your IP is dynamic
  - you do not want to risk locking yourself out

If configured, only listed IPs/CIDRs can reach /admin."

  option_prompt ADMIN_ALLOWED_IPS "Admin allowed IPs/CIDRs, comma-separated" ""

  info_block "Protection mode" \
"Controls brute-force and abuse protection.

Options:
  fail2ban  - protects based on Vaultwarden logs
  crowdsec  - community-driven detection and decisions
  both      - recommended
  none      - not recommended

Recommended:
  both"

  option_prompt PROTECTION_MODE "Protection mode: fail2ban/crowdsec/both/none" "both"
  PROTECTION_MODE="${PROTECTION_MODE,,}"

  case "${PROTECTION_MODE}" in
    fail2ban|crowdsec|both|none) ;;
    *) die "Invalid protection mode." ;;
  esac

  info_block "UFW local firewall" \
"Configures a basic local firewall on the VM.

Allowed:
  22/tcp
  80/tcp
  443/tcp

Important:
  Also configure your cloud firewall.
  Ideally, restrict SSH 22/tcp to your own public IP."

  option_prompt UFW_ENABLE "Enable local UFW firewall? yes/no" "yes"
  UFW_ENABLE="$(normalize_yes_no "${UFW_ENABLE}")"

  info_block "Daily local backup timer" \
"Creates a daily systemd timer for local Vaultwarden backups.

Recommended:
  yes

Important:
  Local backup is not enough.
  Later, configure encrypted off-server backups with restic or similar."

  option_prompt BACKUP_TIMER_ENABLE "Create daily systemd backup timer? yes/no" "yes"
  BACKUP_TIMER_ENABLE="$(normalize_yes_no "${BACKUP_TIMER_ENABLE}")"

  if [[ "${BACKUP_TIMER_ENABLE}" == "yes" ]]; then
    info_block "Backup time" \
"Time when the local daily backup will run.

Format:
  HH:MM

Default:
  03:30"

    option_prompt BACKUP_TIME "Daily backup time, HH:MM" "03:30"
    [[ "${BACKUP_TIME}" =~ ^[0-2][0-9]:[0-5][0-9]$ ]] || die "Invalid backup time."
  fi
}

prepare_dirs() {
  info "Creating directories..."

  mkdir -p "${APP_DIR}" "${DATA_DIR}" "${BACKUP_DIR}" "${DATA_DIR}/caddy-logs"

  chmod 700 "${APP_DIR}" "${DATA_DIR}" "${BACKUP_DIR}"
}

write_env() {
  info "Writing ${ENV_FILE}..."

  local q_domain q_admin_token
  q_domain="$(env_single_quote "https://${DOMAIN_NAME}")"
  q_admin_token="$(env_single_quote "${ADMIN_TOKEN_HASH}")"

  cat > "${ENV_FILE}" <<EOF
DOMAIN=${q_domain}
SIGNUPS_ALLOWED=${SIGNUPS_ALLOWED}
INVITATIONS_ALLOWED=${INVITATIONS_ALLOWED}
ADMIN_TOKEN=${q_admin_token}
EOF

  if [[ "${SMTP_ENABLE}" == "yes" ]]; then
    local q_smtp_host q_smtp_port q_smtp_security
    local q_smtp_from q_smtp_username q_smtp_password

    q_smtp_host="$(env_single_quote "${SMTP_HOST}")"
    q_smtp_port="$(env_single_quote "${SMTP_PORT}")"
    q_smtp_security="$(env_single_quote "${SMTP_SECURITY}")"
    q_smtp_from="$(env_single_quote "${SMTP_FROM}")"
    q_smtp_username="$(env_single_quote "${SMTP_USERNAME}")"
    q_smtp_password="$(env_single_quote "${SMTP_PASSWORD}")"

    cat >> "${ENV_FILE}" <<EOF

SMTP_HOST=${q_smtp_host}
SMTP_PORT=${q_smtp_port}
SMTP_SECURITY=${q_smtp_security}
SMTP_FROM=${q_smtp_from}
SMTP_USERNAME=${q_smtp_username}
SMTP_PASSWORD=${q_smtp_password}
EOF
  fi

  chmod 600 "${ENV_FILE}"
}

validate_env_file() {
  info "Validating .env file..."

  local token_line=""
  token_line="$(grep '^ADMIN_TOKEN=' "${ENV_FILE}" || true)"

  if [[ -z "${token_line}" ]]; then
    die "ADMIN_TOKEN line not found in ${ENV_FILE}."
  fi

  if [[ "${token_line}" == *"[INFO]"* || "${token_line}" == *"[WARN]"* ]]; then
    echo "Current ADMIN_TOKEN line:" >&2
    echo "${token_line}" >&2
    die "Invalid .env: log output was written into ADMIN_TOKEN."
  fi

  if [[ "${token_line}" == ADMIN_TOKEN=\$\$argon2id* ]]; then
    echo "Current ADMIN_TOKEN line:" >&2
    echo "${token_line}" >&2
    die "Invalid ADMIN_TOKEN format. Do not use \$\$argon2id in env_file."
  fi

  case "${token_line}" in
    ADMIN_TOKEN=\'\$argon2id\$*\')
      info ".env ADMIN_TOKEN validation passed."
      ;;
    *)
      echo "Current ADMIN_TOKEN line:" >&2
      echo "${token_line}" >&2
      die "Invalid ADMIN_TOKEN format in ${ENV_FILE}."
      ;;
  esac

  if [[ "${SMTP_ENABLE}" == "no" ]] && grep -q '^SMTP_' "${ENV_FILE}"; then
    die "SMTP is disabled, but SMTP_* variables were written to ${ENV_FILE}."
  fi

  if [[ "${SMTP_ENABLE}" == "yes" ]]; then
    local smtp_security_line=""
    smtp_security_line="$(grep '^SMTP_SECURITY=' "${ENV_FILE}" || true)"

    case "${smtp_security_line}" in
      SMTP_SECURITY=\'starttls\'|SMTP_SECURITY=\'force_tls\'|SMTP_SECURITY=\'off\')
        info ".env SMTP validation passed."
        ;;
      *)
        echo "Current SMTP_SECURITY line:" >&2
        echo "${smtp_security_line}" >&2
        die "Invalid SMTP_SECURITY in ${ENV_FILE}."
        ;;
    esac
  fi
}

build_admin_ip_matcher() {
  local matcher=""

  if [[ -n "${ADMIN_ALLOWED_IPS}" ]]; then
    matcher="@admin_allowed {
    remote_ip"

    IFS=',' read -ra ip_array <<< "${ADMIN_ALLOWED_IPS}"

    local ip
    for ip in "${ip_array[@]}"; do
      ip="$(echo "${ip}" | xargs)"
      [[ -n "${ip}" ]] && matcher+=" ${ip}"
    done

    matcher+="
}"
  fi

  printf '%s' "${matcher}"
}

write_caddyfile() {
  info "Writing ${CADDYFILE}..."

  local admin_ip_matcher
  admin_ip_matcher="$(build_admin_ip_matcher)"

  cat > "${CADDYFILE}" <<EOF
{
    email ${ACME_EMAIL}
}

${DOMAIN_NAME} {
    encode zstd gzip

    log {
        output file /data/access.log {
            roll_size 50MiB
            roll_keep 10
            roll_keep_for 720h
        }
        format json
    }

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "same-origin"
        -Server
    }

EOF

  if [[ -n "${ADMIN_ALLOWED_IPS}" ]]; then
    cat >> "${CADDYFILE}" <<EOF
    ${admin_ip_matcher}

    handle /admin* {
        handle @admin_allowed {
EOF
  else
    cat >> "${CADDYFILE}" <<EOF
    handle /admin* {
EOF
  fi

  if [[ "${ADMIN_BASIC_AUTH_ENABLE}" == "yes" ]]; then
    cat >> "${CADDYFILE}" <<EOF
            basic_auth bcrypt "${ADMIN_BASIC_REALM}" {
                ${ADMIN_BASIC_USER} ${ADMIN_BASIC_HASH}
            }
EOF
  fi

  if [[ -n "${ADMIN_ALLOWED_IPS}" ]]; then
    cat >> "${CADDYFILE}" <<EOF
            reverse_proxy vaultwarden:80 {
                header_up X-Real-IP {remote_host}
                header_up X-Forwarded-For {remote_host}
                header_up X-Forwarded-Proto {scheme}
            }
        }

        respond "Forbidden" 403
    }

EOF
  else
    cat >> "${CADDYFILE}" <<EOF
        reverse_proxy vaultwarden:80 {
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-For {remote_host}
            header_up X-Forwarded-Proto {scheme}
        }
    }

EOF
  fi

  cat >> "${CADDYFILE}" <<EOF
    reverse_proxy vaultwarden:80 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
EOF

  chmod 600 "${CADDYFILE}"
}

write_compose() {
  info "Writing ${COMPOSE_FILE}..."

  cat > "${COMPOSE_FILE}" <<'EOF'
services:
  vaultwarden:
    image: vaultwarden/server:latest
    container_name: vaultwarden
    restart: unless-stopped
    env_file:
      - .env
    environment:
      ROCKET_ADDRESS: "0.0.0.0"
      ROCKET_PORT: "80"
      LOG_FILE: "/data/vaultwarden.log"
      LOG_LEVEL: "warn"
      EXTENDED_LOGGING: "true"
      IP_HEADER: "X-Forwarded-For"
    volumes:
      - ./data:/data
    networks:
      - vaultwarden_net

  caddy:
    image: caddy:2
    container_name: vaultwarden-caddy
    restart: unless-stopped
    depends_on:
      - vaultwarden
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./data/caddy-logs:/data
      - caddy_data:/srv
      - caddy_config:/config
    networks:
      - vaultwarden_net

networks:
  vaultwarden_net:
    driver: bridge

volumes:
  caddy_data:
  caddy_config:
EOF

  chmod 600 "${COMPOSE_FILE}"
}

validate_compose_config() {
  info "Validating Docker Compose config..."

  cd "${APP_DIR}"

  docker compose config >/tmp/vaultwarden-compose-config.out

  if ! grep -q 'ADMIN_TOKEN' /tmp/vaultwarden-compose-config.out; then
    die "ADMIN_TOKEN not found in rendered Docker Compose config."
  fi

  if grep -q 'ADMIN_TOKEN: ""' /tmp/vaultwarden-compose-config.out; then
    die "ADMIN_TOKEN is empty in rendered Docker Compose config."
  fi

  if ! grep -q '\$argon2id\$' /tmp/vaultwarden-compose-config.out; then
    echo "Rendered config ADMIN_TOKEN line:" >&2
    grep 'ADMIN_TOKEN' /tmp/vaultwarden-compose-config.out >&2 || true
    die "Rendered config does not contain Argon2id token."
  fi

  if [[ "${SMTP_ENABLE}" == "no" ]] && grep -q 'SMTP_' /tmp/vaultwarden-compose-config.out; then
    die "SMTP is disabled, but SMTP_* variables exist in rendered Docker Compose config."
  fi

  info "Docker Compose config validation passed."
}

validate_caddyfile() {
  info "Validating Caddyfile syntax..."

  docker run --rm \
    -v "${CADDYFILE}:/etc/caddy/Caddyfile:ro" \
    caddy:2 \
    caddy validate --config /etc/caddy/Caddyfile
}

start_stack() {
  info "Starting Vaultwarden stack..."

  cd "${APP_DIR}"

  docker compose pull
  validate_caddyfile

  docker compose up -d
  docker compose ps

  sleep 5

  if ! docker ps --format '{{.Names}}' | grep -qx 'vaultwarden'; then
    docker compose logs --tail=100 vaultwarden || true
    die "Vaultwarden container is not running."
  fi

  if ! docker ps --format '{{.Names}}' | grep -qx 'vaultwarden-caddy'; then
    docker compose logs --tail=100 caddy || true
    die "Caddy container is not running."
  fi
}

write_backup_scripts() {
  info "Writing backup and restore scripts..."

  cat > /usr/local/sbin/vw-backup <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR}"
DATA_DIR="${DATA_DIR}"
BACKUP_DIR="${BACKUP_DIR}"

timestamp="\$(date +%Y%m%d-%H%M%S)"
workdir="\${BACKUP_DIR}/.tmp-\${timestamp}"
archive="\${BACKUP_DIR}/vaultwarden-\${timestamp}.tar.gz"

mkdir -p "\${workdir}" "\${BACKUP_DIR}"

if [[ -f "\${DATA_DIR}/db.sqlite3" ]]; then
  sqlite3 "\${DATA_DIR}/db.sqlite3" ".backup '\${workdir}/db.sqlite3'"
fi

mkdir -p "\${workdir}/data"

rsync -a --delete \
  --exclude 'db.sqlite3' \
  --exclude 'db.sqlite3-wal' \
  --exclude 'db.sqlite3-shm' \
  --exclude 'caddy-logs' \
  "\${DATA_DIR}/" "\${workdir}/data/"

cp -a "\${APP_DIR}/docker-compose.yml" "\${workdir}/docker-compose.yml"
cp -a "\${APP_DIR}/Caddyfile" "\${workdir}/Caddyfile"

if [[ -f "\${APP_DIR}/.env" ]]; then
  cp -a "\${APP_DIR}/.env" "\${workdir}/env.redacted"
  sed -i -E 's/^(ADMIN_TOKEN|SMTP_PASSWORD)=.*/\\1=REDACTED/' "\${workdir}/env.redacted"
fi

tar -C "\${workdir}" -czf "\${archive}" .
rm -rf "\${workdir}"

find "\${BACKUP_DIR}" -type f -name 'vaultwarden-*.tar.gz' -mtime +14 -delete

echo "\${archive}"
EOF

  chmod 700 /usr/local/sbin/vw-backup

  cat > /usr/local/sbin/vw-restore <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR}"
DATA_DIR="${DATA_DIR}"

archive="\${1:-}"

if [[ -z "\${archive}" || ! -f "\${archive}" ]]; then
  echo "Usage: vw-restore /path/to/vaultwarden-YYYYMMDD-HHMMSS.tar.gz" >&2
  exit 1
fi

restore_dir="\$(mktemp -d)"
trap 'rm -rf "\${restore_dir}"' EXIT

tar -xzf "\${archive}" -C "\${restore_dir}"

cd "\${APP_DIR}"
docker compose down

mkdir -p "\${DATA_DIR}"

if [[ -d "\${restore_dir}/data" ]]; then
  rsync -a --delete "\${restore_dir}/data/" "\${DATA_DIR}/"
fi

if [[ -f "\${restore_dir}/db.sqlite3" ]]; then
  cp "\${restore_dir}/db.sqlite3" "\${DATA_DIR}/db.sqlite3"
fi

chmod -R 700 "\${DATA_DIR}"

docker compose up -d

echo "Restore completed."
EOF

  chmod 700 /usr/local/sbin/vw-restore
}

install_backup_timer() {
  [[ "${BACKUP_TIMER_ENABLE}" == "yes" ]] || return

  info "Installing systemd backup timer..."

  local hour minute
  hour="${BACKUP_TIME%:*}"
  minute="${BACKUP_TIME#*:}"

  cat > /etc/systemd/system/vaultwarden-backup.service <<EOF
[Unit]
Description=Vaultwarden backup

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vw-backup
EOF

  cat > /etc/systemd/system/vaultwarden-backup.timer <<EOF
[Unit]
Description=Daily Vaultwarden backup timer

[Timer]
OnCalendar=*-*-* ${hour}:${minute}:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now vaultwarden-backup.timer
}

configure_ufw() {
  [[ "${UFW_ENABLE}" == "yes" ]] || return

  info "Installing and configuring UFW..."

  apt-get install -y ufw

  warn "UFW will allow TCP/22 from anywhere."
  warn "Restrict SSH in cloud firewall to your public IP."

  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing

  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp

  ufw --force enable
  ufw status verbose
}

install_fail2ban() {
  info "Installing Fail2ban..."

  apt-get install -y fail2ban iptables

  cat > /etc/fail2ban/filter.d/vaultwarden.conf <<'EOF'
[Definition]
failregex = ^.*Username or password is incorrect\. Try again\. IP: <HOST>\. Username:.*$
            ^.*Invalid admin token\. IP: <HOST>.*$
            ^.*2FA token not provided\. IP: <HOST>.*$
ignoreregex =
EOF

  cat > /etc/fail2ban/jail.d/vaultwarden.local <<EOF
[vaultwarden]
enabled = true
port = 80,443
filter = vaultwarden
logpath = ${DATA_DIR}/vaultwarden.log
backend = auto

maxretry = 5
findtime = 10m
bantime = 1h

banaction = iptables-allports
chain = DOCKER-USER
EOF

  systemctl enable --now fail2ban
  systemctl restart fail2ban

  fail2ban-client status || true
  fail2ban-client status vaultwarden || true

  info "Fail2ban configured for Vaultwarden using DOCKER-USER chain."
}

install_crowdsec() {
  info "Installing CrowdSec Security Engine and firewall bouncer..."

  if ! command -v crowdsec >/dev/null 2>&1; then
    curl -fsSL https://install.crowdsec.net | sh
    apt-get update
    apt-get install -y crowdsec
  fi

  if ! dpkg -l | grep -q '^ii  crowdsec-firewall-bouncer'; then
    apt-get install -y crowdsec-firewall-bouncer || true
  fi

  cscli collections install crowdsecurity/linux || true
  cscli collections install crowdsecurity/sshd || true
  cscli collections install crowdsecurity/caddy || true

  mkdir -p /etc/crowdsec/acquis.d

  cat > /etc/crowdsec/acquis.d/vaultwarden-caddy.yaml <<EOF
filenames:
  - ${DATA_DIR}/caddy-logs/access.log
labels:
  type: caddy
EOF

  systemctl enable --now crowdsec
  systemctl restart crowdsec

  if systemctl list-unit-files | grep -q '^crowdsec-firewall-bouncer.service'; then
    systemctl enable --now crowdsec-firewall-bouncer
    systemctl restart crowdsec-firewall-bouncer || warn "crowdsec-firewall-bouncer restart failed. Check journalctl -xeu crowdsec-firewall-bouncer."
  else
    warn "crowdsec-firewall-bouncer.service was not found. CrowdSec will detect events, but may not block IPs."
  fi

  install_crowdsec_docker_enforcement

  cscli bouncers list || true
  cscli metrics || true

  info "CrowdSec configured with linux, sshd, caddy collections and Docker enforcement sync."
}

install_crowdsec_docker_enforcement() {
  info "Installing CrowdSec Docker enforcement via ipset and DOCKER-USER..."

  apt-get install -y ipset iptables jq

  cat > /usr/local/sbin/crowdsec-sync-ipset <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

IPSET_V4="crowdsec-blacklists"

ipset create "$IPSET_V4" hash:net family inet -exist

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

# Extract IPv4 decisions from CrowdSec JSON.
# Different cscli versions may expose fields slightly differently,
# so this intentionally depends only on scope/value.
cscli decisions list -o json \
  | jq -r '
      .. | objects
      | select(
          ((.scope? // .Scope? // "") | ascii_downcase) == "ip"
        )
      | (.value? // .Value? // .ip? // .IP? // empty)
    ' \
  | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
  | sort -u > "$tmp_file" || true

ipset flush "$IPSET_V4"

while read -r ip; do
  [[ -n "$ip" ]] && ipset add "$IPSET_V4" "$ip" -exist
done < "$tmp_file"

iptables -C DOCKER-USER -m set --match-set "$IPSET_V4" src -j DROP 2>/dev/null || \
iptables -I DOCKER-USER 1 -m set --match-set "$IPSET_V4" src -j DROP
EOF

  chmod 700 /usr/local/sbin/crowdsec-sync-ipset

  cat > /etc/systemd/system/crowdsec-sync-ipset.service <<'EOF'
[Unit]
Description=Sync CrowdSec decisions into ipset for Docker DOCKER-USER enforcement
After=crowdsec.service docker.service
Requires=crowdsec.service docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/crowdsec-sync-ipset
EOF

  cat > /etc/systemd/system/crowdsec-sync-ipset.timer <<'EOF'
[Unit]
Description=Run CrowdSec ipset sync every 30 seconds

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now crowdsec-sync-ipset.timer

  /usr/local/sbin/crowdsec-sync-ipset || warn "Initial CrowdSec ipset sync failed."

  systemctl status crowdsec-sync-ipset.timer --no-pager || true
  ipset list crowdsec-blacklists || true
  iptables -L DOCKER-USER -n -v --line-numbers || true
}

install_protection() {
  case "${PROTECTION_MODE}" in
    fail2ban)
      install_fail2ban
      ;;
    crowdsec)
      install_crowdsec
      ;;
    both)
      install_fail2ban
      install_crowdsec
      ;;
    none)
      warn "No Fail2ban/CrowdSec protection selected."
      ;;
  esac
}

run_initial_backup() {
  info "Running initial backup..."

  /usr/local/sbin/vw-backup || warn "Initial backup failed."
}

print_summary() {
  cat <<EOF

==============================================================================
Vaultwarden deployment completed.

URL:
  https://${DOMAIN_NAME}

Admin panel:
  https://${DOMAIN_NAME}/admin

Files:
  App directory:      ${APP_DIR}
  Data directory:     ${DATA_DIR}
  Compose file:       ${COMPOSE_FILE}
  Caddyfile:          ${CADDYFILE}
  Env file:           ${ENV_FILE}
  Backup directory:   ${BACKUP_DIR}

Useful commands:
  cd ${APP_DIR} && docker compose ps
  cd ${APP_DIR} && docker compose logs -f
  cd ${APP_DIR} && docker compose logs -f vaultwarden
  cd ${APP_DIR} && docker compose logs -f caddy

Check .env:
  grep '^ADMIN_TOKEN=' ${ENV_FILE}
  grep -E '^(SIGNUPS_ALLOWED|INVITATIONS_ALLOWED)=' ${ENV_FILE}
  grep '^SMTP_' ${ENV_FILE} || echo "SMTP disabled"

Check rendered config:
  cd ${APP_DIR} && docker compose config | grep -E 'ADMIN_TOKEN|SMTP_|DOMAIN|SIGNUPS_ALLOWED|INVITATIONS_ALLOWED'

Backup:
  /usr/local/sbin/vw-backup

Restore:
  /usr/local/sbin/vw-restore /path/to/vaultwarden-YYYYMMDD-HHMMSS.tar.gz

Adding users:
  Keep SIGNUPS_ALLOWED=false.
  Keep INVITATIONS_ALLOWED=true.
  Add users via:
    https://${DOMAIN_NAME}/admin
    Users -> Invite user

If you temporarily changed invitation settings:
  cd ${APP_DIR}
  sed -i 's/^SIGNUPS_ALLOWED=.*/SIGNUPS_ALLOWED=false/' .env
  sed -i 's/^INVITATIONS_ALLOWED=.*/INVITATIONS_ALLOWED=true/' .env
  docker compose up -d --force-recreate vaultwarden

Reset Caddy Basic Auth:
  NEW_PASS='new-caddy-password'
  NEW_HASH="\$(docker run --rm caddy:2 caddy hash-password --plaintext "\$NEW_PASS")"
  nano ${CADDYFILE}
  cd ${APP_DIR} && docker compose up -d --force-recreate caddy

Test Caddy Basic Auth:
  curl -I https://${DOMAIN_NAME}/admin
  curl -I -u '${ADMIN_BASIC_USER}:YOUR_CADDY_BASIC_AUTH_PASSWORD' https://${DOMAIN_NAME}/admin

Fail2ban:
  fail2ban-client status
  fail2ban-client status vaultwarden
  iptables -L DOCKER-USER -n -v --line-numbers

Fail2ban manual test:
  fail2ban-client set vaultwarden banip TEST_IP
  fail2ban-client set vaultwarden unbanip TEST_IP

CrowdSec:
  cscli metrics
  cscli decisions list
  cscli bouncers list
  systemctl status crowdsec --no-pager
  systemctl status crowdsec-firewall-bouncer --no-pager

CrowdSec Docker enforcement:
  systemctl status crowdsec-sync-ipset.timer --no-pager
  /usr/local/sbin/crowdsec-sync-ipset
  ipset list crowdsec-blacklists
  iptables -L DOCKER-USER -n -v --line-numbers

CrowdSec manual test:
  cscli decisions add --ip TEST_IP --duration 5m --reason "manual test"
  /usr/local/sbin/crowdsec-sync-ipset
  ipset list crowdsec-blacklists
  cscli decisions delete --ip TEST_IP
  /usr/local/sbin/crowdsec-sync-ipset

SMTP examples:

  GMAIL:
    SMTP_HOST='smtp.gmail.com'
    SMTP_PORT='587'
    SMTP_SECURITY='starttls'
    SMTP_FROM='yourname+vaultwarden@gmail.com'
    SMTP_USERNAME='yourname@gmail.com'
    SMTP_PASSWORD='GOOGLE_APP_PASSWORD'

  SMTP2GO:
    SMTP_HOST='mail.smtp2go.com'
    SMTP_PORT='2525'
    SMTP_SECURITY='starttls'
    SMTP_FROM='vaultwarden@example.com'
    SMTP_USERNAME='SMTP2GO_SMTP_USERNAME'
    SMTP_PASSWORD='SMTP2GO_SMTP_PASSWORD'

  BREVO:
    SMTP_HOST='smtp-relay.brevo.com'
    SMTP_PORT='2525'
    SMTP_SECURITY='starttls'
    SMTP_FROM='vaultwarden@example.com'
    SMTP_USERNAME='BREVO_SMTP_LOGIN'
    SMTP_PASSWORD='BREVO_SMTP_KEY'

Quick Manual SMTP Tests:
  nc -vz smtp-relay.brevo.com 587
  nc -vz smtp-relay.brevo.com 2525
  nc -vz smtp-relay.brevo.com 465
  nc -vz smtp-relay.brevo.com 25

Cloud firewall checklist:
  1. TCP 22 only from your public IP
  2. TCP 80 from 0.0.0.0/0 and ::/0
  3. TCP 443 from 0.0.0.0/0 and ::/0
  4. Do not expose Docker internal ports
  5. Do not expose Caddy admin API port 2019

Security notes:
  1. DNS A/AAAA record for ${DOMAIN_NAME} must point to this server.
  2. TCP 80 and 443 must be reachable for Let's Encrypt.
  3. Public registration is currently: ${SIGNUPS_ALLOWED}
  4. Admin/user invitations are currently: ${INVITATIONS_ALLOWED}
  5. Recommended user management model:
     SIGNUPS_ALLOWED=false
     INVITATIONS_ALLOWED=true
     Add users only from /admin -> Users -> Invite user
  6. Keep ${ENV_FILE} private.
  7. Move backups off-server. Local-only backup is not enough.
  8. SMTP is optional. If disabled, SMTP_* variables are not written.
  9. Fail2ban uses DOCKER-USER chain.
 10. CrowdSec Docker blocking is enforced by:
     cscli decisions -> ipset crowdsec-blacklists -> DOCKER-USER DROP.
 11. Caddy /admin Basic Auth uses a dedicated realm:
     ${ADMIN_BASIC_REALM}
     If browser credentials get stuck, change the realm or clear site data.
 12. For Cloudflare DNS, keep Vaultwarden DNS record as DNS only, not proxied.

==============================================================================
EOF
}

main() {
  need_root
  detect_os

  install_base_packages
  install_docker
  configure_docker_log_rotation

  collect_inputs
  prepare_dirs

  write_env
  validate_env_file

  write_caddyfile
  write_compose

  validate_compose_config
  start_stack

  write_backup_scripts
  install_backup_timer
  configure_ufw
  install_protection
  run_initial_backup

  print_summary
}

main "$@"
