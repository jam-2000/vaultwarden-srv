#!/usr/bin/env bash
set -Eeuo pipefail

# ==============================================================================
# vw-update-stack
#
# Safe updater for Vaultwarden stack installed by install-vaultwarden.sh
#
# Updates:
#   - vaultwarden/server image
#   - caddy image
#   - Docker Compose containers
#
# Preserves:
#   - /opt/vaultwarden/data
#   - /opt/vaultwarden/.env
#   - /opt/vaultwarden/Caddyfile
#   - /opt/vaultwarden/docker-compose.yml
#   - Docker named volumes
#   - Caddy certificates
#   - Vaultwarden database
#   - attachments, sends, icons, configs
#
# Safety:
#   - creates backup before update
#   - saves pre-update config snapshots
#   - captures current image IDs
#   - validates Compose config
#   - checks containers after update
#   - removes old unused images only after successful update
#
# Does NOT run:
#   - docker compose down -v
#   - docker system prune -a
#   - rm -rf data
# ==============================================================================

APP_DIR="/opt/vaultwarden"
BACKUP_SCRIPT="/usr/local/sbin/vw-backup"
BACKUP_DIR="/opt/vaultwarden-backups"

VAULTWARDEN_SERVICE="vaultwarden"
CADDY_SERVICE="caddy"

VAULTWARDEN_CONTAINER="vaultwarden"
CADDY_CONTAINER="vaultwarden-caddy"

HEALTHCHECK_TIMEOUT_SECONDS="90"
HEALTHCHECK_INTERVAL_SECONDS="5"

TS="$(date +%Y%m%d-%H%M%S)"
PREUPDATE_DIR="${APP_DIR}/pre-update-${TS}"

C_RESET=""
C_RED=""
C_GREEN=""
C_YELLOW=""
C_BLUE=""
C_BOLD=""

if [[ -t 1 ]]; then
  C_RESET="\033[0m"
  C_RED="\033[31m"
  C_GREEN="\033[32m"
  C_YELLOW="\033[33m"
  C_BLUE="\033[34m"
  C_BOLD="\033[1m"
fi

info() {
  echo -e "${C_GREEN}[INFO]${C_RESET} $*"
}

warn() {
  echo -e "${C_YELLOW}[WARN]${C_RESET} $*" >&2
}

die() {
  echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2
  exit 1
}

section() {
  echo
  echo -e "${C_BOLD}${C_BLUE}================================================================================${C_RESET}"
  echo -e "${C_BOLD}${C_BLUE}$*${C_RESET}"
  echo -e "${C_BOLD}${C_BLUE}================================================================================${C_RESET}"
}

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo /usr/local/sbin/vw-update-stack"
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

check_layout() {
  section "Checking Vaultwarden stack layout"

  [[ -d "${APP_DIR}" ]] || die "APP_DIR not found: ${APP_DIR}"
  [[ -f "${APP_DIR}/docker-compose.yml" ]] || die "docker-compose.yml not found in ${APP_DIR}"
  [[ -f "${APP_DIR}/.env" ]] || die ".env not found in ${APP_DIR}"
  [[ -f "${APP_DIR}/Caddyfile" ]] || die "Caddyfile not found in ${APP_DIR}"
  [[ -d "${APP_DIR}/data" ]] || die "data directory not found: ${APP_DIR}/data"

  cd "${APP_DIR}"

  docker compose version >/dev/null || die "Docker Compose plugin is not working."

  info "Stack directory: ${APP_DIR}"
  info "Data directory: ${APP_DIR}/data"
}

show_current_state() {
  section "Current stack state"

  cd "${APP_DIR}"

  docker compose ps || true

  echo
  info "Current Compose images:"
  docker compose images || true

  echo
  info "Current disk usage:"
  docker system df || true
}

capture_current_images_and_configs() {
  section "Capturing current image IDs and configs"

  cd "${APP_DIR}"

  mkdir -p "${PREUPDATE_DIR}"

  docker inspect "${VAULTWARDEN_CONTAINER}" \
    --format '{{.Image}}' > "${PREUPDATE_DIR}/vaultwarden.image_id" 2>/dev/null \
    || warn "Could not capture current Vaultwarden image ID."

  docker inspect "${CADDY_CONTAINER}" \
    --format '{{.Image}}' > "${PREUPDATE_DIR}/caddy.image_id" 2>/dev/null \
    || warn "Could not capture current Caddy image ID."

  docker compose config > "${PREUPDATE_DIR}/docker-compose.rendered.before.yml"

  cp -a "${APP_DIR}/.env" "${PREUPDATE_DIR}/.env.before"
  cp -a "${APP_DIR}/Caddyfile" "${PREUPDATE_DIR}/Caddyfile.before"
  cp -a "${APP_DIR}/docker-compose.yml" "${PREUPDATE_DIR}/docker-compose.yml.before"

  chmod 700 "${PREUPDATE_DIR}"
  chmod 600 "${PREUPDATE_DIR}/"* || true

  info "Pre-update metadata saved to: ${PREUPDATE_DIR}"
}

run_backup() {
  section "Running pre-update backup"

  mkdir -p "${BACKUP_DIR}"

  if [[ -x "${BACKUP_SCRIPT}" ]]; then
    local backup_output
    backup_output="$("${BACKUP_SCRIPT}")"

    echo "${backup_output}"

    if echo "${backup_output}" | grep -qE '^/.+vaultwarden-.+\.tar\.gz$'; then
      info "Backup completed."
    else
      warn "Backup script completed, but output archive path was not detected."
    fi
  else
    warn "Backup script not found or not executable: ${BACKUP_SCRIPT}"
    warn "Creating fallback backup archive."

    local fallback_archive
    fallback_archive="${BACKUP_DIR}/vaultwarden-fallback-preupdate-${TS}.tar.gz"

    tar \
      --exclude="${APP_DIR}/data/caddy-logs" \
      -czf "${fallback_archive}" \
      -C "${APP_DIR}" \
      .env Caddyfile docker-compose.yml data

    chmod 600 "${fallback_archive}"

    info "Fallback backup created: ${fallback_archive}"
  fi
}

validate_before_update() {
  section "Validating configuration before update"

  cd "${APP_DIR}"

  docker compose config >/tmp/vw-compose-config-before-update.yml

  if grep -q 'ADMIN_TOKEN' "${APP_DIR}/.env"; then
    info ".env contains ADMIN_TOKEN."
  else
    die ".env does not contain ADMIN_TOKEN."
  fi

  if [[ -f "${APP_DIR}/data/db.sqlite3" ]]; then
    info "SQLite database found: ${APP_DIR}/data/db.sqlite3"

    if command -v sqlite3 >/dev/null 2>&1; then
      sqlite3 "${APP_DIR}/data/db.sqlite3" "PRAGMA integrity_check;" \
        | grep -qx "ok" \
        && info "SQLite integrity check passed." \
        || die "SQLite integrity check failed."
    else
      warn "sqlite3 command not found. Skipping SQLite integrity check."
    fi
  else
    warn "SQLite database not found. This may be normal only for a fresh install."
  fi

  if grep -q 'vaultwarden/server' /tmp/vw-compose-config-before-update.yml; then
    info "Vaultwarden image found in rendered Compose config."
  else
    warn "vaultwarden/server image not found in rendered Compose config."
  fi

  if grep -q 'caddy' /tmp/vw-compose-config-before-update.yml; then
    info "Caddy image found in rendered Compose config."
  else
    warn "caddy image not found in rendered Compose config."
  fi
}

pull_images() {
  section "Pulling updated Docker images"

  cd "${APP_DIR}"

  docker compose pull
}

recreate_stack() {
  section "Recreating containers without deleting data"

  cd "${APP_DIR}"

  # Important:
  #   - no down -v
  #   - no volume deletion
  #   - no data directory deletion
  docker compose up -d --remove-orphans
}

wait_for_container_running() {
  local container_name="$1"
  local elapsed=0

  while (( elapsed < HEALTHCHECK_TIMEOUT_SECONDS )); do
    if docker ps --format '{{.Names}}' | grep -qx "${container_name}"; then
      return 0
    fi

    sleep "${HEALTHCHECK_INTERVAL_SECONDS}"
    elapsed=$((elapsed + HEALTHCHECK_INTERVAL_SECONDS))
  done

  return 1
}

check_after_update() {
  section "Checking stack after update"

  cd "${APP_DIR}"

  docker compose ps

  if ! wait_for_container_running "${VAULTWARDEN_CONTAINER}"; then
    warn "Vaultwarden container did not become running in time."
    docker compose logs --tail=150 "${VAULTWARDEN_SERVICE}" || true
    return 1
  fi

  if ! wait_for_container_running "${CADDY_CONTAINER}"; then
    warn "Caddy container did not become running in time."
    docker compose logs --tail=150 "${CADDY_SERVICE}" || true
    return 1
  fi

  info "Both containers are running."

  echo
  info "Recent Vaultwarden logs:"
  docker compose logs --tail=80 "${VAULTWARDEN_SERVICE}" || true

  echo
  info "Recent Caddy logs:"
  docker compose logs --tail=80 "${CADDY_SERVICE}" || true

  return 0
}

rollback_images() {
  section "Attempting rollback to previous local image IDs"

  cd "${APP_DIR}"

  local old_vw_image=""
  local old_caddy_image=""

  if [[ -f "${PREUPDATE_DIR}/vaultwarden.image_id" ]]; then
    old_vw_image="$(cat "${PREUPDATE_DIR}/vaultwarden.image_id" || true)"
  fi

  if [[ -f "${PREUPDATE_DIR}/caddy.image_id" ]]; then
    old_caddy_image="$(cat "${PREUPDATE_DIR}/caddy.image_id" || true)"
  fi

  if [[ -z "${old_vw_image}" && -z "${old_caddy_image}" ]]; then
    warn "No previous image IDs captured. Automatic rollback is not possible."
    return 1
  fi

  cp -a "${APP_DIR}/docker-compose.yml" "${PREUPDATE_DIR}/docker-compose.yml.failed-update"

  local rollback_compose="${PREUPDATE_DIR}/docker-compose.rollback.yml"

  cp -a "${APP_DIR}/docker-compose.yml" "${rollback_compose}"

  if [[ -n "${old_vw_image}" ]]; then
    info "Previous Vaultwarden image ID: ${old_vw_image}"
    sed -i -E "0,/image:[[:space:]]*vaultwarden\/server:.*/s|image:[[:space:]]*vaultwarden/server:.*|image: ${old_vw_image}|" "${rollback_compose}"
  fi

  if [[ -n "${old_caddy_image}" ]]; then
    info "Previous Caddy image ID: ${old_caddy_image}"
    sed -i -E "0,/image:[[:space:]]*caddy:.*/s|image:[[:space:]]*caddy:.*|image: ${old_caddy_image}|" "${rollback_compose}"
  fi

  info "Starting rollback Compose file..."

  docker compose -f "${rollback_compose}" up -d --remove-orphans

  sleep 10

  docker compose -f "${rollback_compose}" ps || true

  if docker ps --format '{{.Names}}' | grep -qx "${VAULTWARDEN_CONTAINER}" \
    && docker ps --format '{{.Names}}' | grep -qx "${CADDY_CONTAINER}"; then
    warn "Rollback containers are running using previous image IDs."
    warn "Main docker-compose.yml was not modified."
    warn "Rollback Compose file:"
    warn "  ${rollback_compose}"
    return 0
  fi

  warn "Rollback attempt did not fully recover the stack."
  return 1
}

cleanup_old_images_after_success() {
  section "Removing old unused Docker images"

  echo
  info "Docker disk usage before cleanup:"
  docker system df || true

  echo
  info "Removing dangling images..."
  docker image prune -f || warn "docker image prune failed."

  echo
  info "Removing unused images older than 24 hours..."
  docker image prune -a -f --filter "until=24h" || warn "docker image prune -a failed."

  echo
  info "Docker disk usage after cleanup:"
  docker system df || true

  echo
  warn "The script intentionally did NOT remove:"
  warn "  - containers"
  warn "  - volumes"
  warn "  - networks"
  warn "  - build cache"
  warn "  - active images"
}

print_final_state() {
  section "Final stack state"

  cd "${APP_DIR}"

  docker compose ps || true

  echo
  info "Compose images:"
  docker compose images || true

  echo
  info "Container image IDs:"
  docker inspect "${VAULTWARDEN_CONTAINER}" --format 'vaultwarden: {{.Image}}' 2>/dev/null || true
  docker inspect "${CADDY_CONTAINER}" --format 'caddy:        {{.Image}}' 2>/dev/null || true

  echo
  info "Pre-update metadata:"
  echo "  ${PREUPDATE_DIR}"

  echo
  info "Backup directory:"
  echo "  ${BACKUP_DIR}"
}

print_success_summary() {
  section "Update completed successfully"

  cat <<MSG
Vaultwarden stack was updated successfully.

Preserved:
  ${APP_DIR}/data
  ${APP_DIR}/.env
  ${APP_DIR}/Caddyfile
  ${APP_DIR}/docker-compose.yml
  Docker volumes

Backup was created before update.

Old unused Docker images were cleaned after successful update.

Manual checks:

  cd ${APP_DIR}
  sudo docker compose ps
  sudo docker compose logs --tail=100 vaultwarden
  sudo docker compose logs --tail=100 caddy

Open:

  https://YOUR_DOMAIN
  https://YOUR_DOMAIN/admin

For /admin without Basic Auth credentials, HTTP 401 is expected.
MSG
}

print_failure_summary() {
  section "Update failed or rollback required manual attention"

  cat <<MSG
The script did not delete your data.

Check:

  cd ${APP_DIR}
  sudo docker compose ps
  sudo docker compose logs --tail=200 vaultwarden
  sudo docker compose logs --tail=200 caddy

Pre-update files:
  ${PREUPDATE_DIR}

Backups:
  ${BACKUP_DIR}

Manual restore example:

  sudo /usr/local/sbin/vw-restore ${BACKUP_DIR}/vaultwarden-YYYYMMDD-HHMMSS.tar.gz
MSG
}

main() {
  need_root

  need_command docker
  need_command tar
  need_command cp
  need_command grep
  need_command sed

  check_layout
  show_current_state
  capture_current_images_and_configs
  run_backup
  validate_before_update
  pull_images
  recreate_stack

  if check_after_update; then
    cleanup_old_images_after_success
    print_final_state
    print_success_summary
    exit 0
  fi

  warn "Post-update check failed. Starting rollback attempt."

  if rollback_images; then
    print_final_state

    cat <<MSG

Rollback completed.

Your data and config were preserved.

Check logs:

  cd ${APP_DIR}
  sudo docker compose logs --tail=200 vaultwarden
  sudo docker compose logs --tail=200 caddy

Pre-update files:
  ${PREUPDATE_DIR}

Backup directory:
  ${BACKUP_DIR}

Old images were NOT cleaned because update failed and rollback was needed.
MSG

    exit 2
  fi

  print_failure_summary
  exit 1
}

main "$@"
EOF
