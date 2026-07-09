#!/usr/bin/env bash
set -Eeuo pipefail

BACKUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SITES_DIR="${HOME}/Projects/sites"
DEFAULT_PHP_VERSION="8.4"
DEFAULT_DB_VERSION="11.8"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1"
    exit 1
  }
}

prompt() {
  local var_name="$1"
  local message="$2"
  local default="${3:-}"
  local input

  if [[ -n "$default" ]]; then
    read -r -p "$message [$default]: " input
    input="${input:-$default}"
  else
    read -r -p "$message: " input
  fi

  printf -v "$var_name" '%s' "$input"
}

confirm() {
  local message="$1"
  local choice
  read -r -p "$message (y/n): " choice
  [[ "$choice" =~ ^[Yy]$ ]]
}

confirm_default_yes() {
  local message="$1"
  local choice
  read -r -p "$message (Y/n): " choice
  [[ -z "$choice" || "$choice" =~ ^[Yy]$ ]]
}

slugify() {
  python3 - "$1" <<'PY'
import re
import sys

value = sys.argv[1].strip().lower()
value = re.sub(r'^https?://', '', value)
value = value.strip('/')
value = re.sub(r'^www\.', '', value)
value = re.sub(r'[^a-z0-9]+', '-', value).strip('-')
print(value or 'synchy-site')
PY
}

path_join() {
  local base="$1"
  local child="$2"

  if [[ -z "$child" ]]; then
    printf '%s\n' "$base"
  else
    printf '%s/%s\n' "$base" "$child"
  fi
}

choose_wordpress_source() {
  local extract_dir="$1"

  if [[ -d "$extract_dir/staging/wp-admin" && -d "$extract_dir/staging/wp-content" ]]; then
    printf '%s\n' "$extract_dir/staging"
    return
  fi

  printf '%s\n' "$extract_dir"
}

load_backups() {
  python3 - "$BACKUP_DIR" <<'PY'
import datetime as dt
import json
import pathlib
import re
import sys

backup_dir = pathlib.Path(sys.argv[1])
rows = []

for manifest_path in sorted(backup_dir.glob("*-manifest.json")):
    try:
        manifest = json.loads(manifest_path.read_text())
    except Exception:
        continue

    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), dict) else {}
    archive_name = artifacts.get("archive", {}).get("filename") if isinstance(artifacts.get("archive"), dict) else ""
    installer_name = artifacts.get("installer", {}).get("filename") if isinstance(artifacts.get("installer"), dict) else ""
    fallback_name = manifest_path.name
    if fallback_name.endswith("-manifest.json"):
        fallback_name = fallback_name[:-len("-manifest.json")]
    package_name = str(manifest.get("package_name") or fallback_name)
    archive_path = backup_dir / archive_name if archive_name else backup_dir / f"{package_name}.zip"
    installer_path = backup_dir / installer_name if installer_name else backup_dir / f"{package_name}-installer.php"

    if not archive_path.is_file() or not installer_path.is_file():
        continue

    created_raw = str(manifest.get("created_at_gmt") or "")
    created_display = created_raw
    sort_key = created_raw
    if created_raw:
        try:
            parsed = dt.datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
            sort_key = parsed.isoformat()
            created_display = parsed.strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            pass

    site = manifest.get("site") if isinstance(manifest.get("site"), dict) else {}
    home_url = str(site.get("home_url") or site.get("site_url") or "")
    host = re.sub(r"^https?://", "", home_url).strip("/").split("/")[0]
    host = re.sub(r"^www\.", "", host)
    host_base = host.split(".")[0].lower()
    host_base = re.sub(r"[^a-z0-9]+", "", host_base)
    for suffix in ("shoffman", "hoffman"):
        if host_base.endswith(suffix) and len(host_base) > len(suffix):
            host_base = host_base[:-len(suffix)]
            break
    suggested = host_base or "site"

    rows.append({
        "sort": sort_key,
        "manifest": str(manifest_path),
        "archive": str(archive_path),
        "installer": str(installer_path),
        "package": package_name,
        "created": created_display or "Unknown date",
        "home": home_url or "Unknown source URL",
        "prefix": str(site.get("db_prefix") or "wp_"),
        "suggested": suggested,
        "size": str(artifacts.get("archive", {}).get("size_bytes") or archive_path.stat().st_size),
    })

for row in sorted(rows, key=lambda item: item["sort"], reverse=True):
    print("\t".join(row[key].replace("\t", " ") for key in ("manifest", "archive", "installer", "package", "created", "home", "prefix", "suggested", "size")))
PY
}

select_backup() {
  local count="$1"

  if [[ "$count" -eq 1 ]]; then
    SELECTED_INDEX=0
    return
  fi

  if [[ ! -t 0 ]]; then
    local number
    read -r -p "Select backup number: " number
    [[ "$number" =~ ^[0-9]+$ ]] || { echo "Invalid selection"; exit 1; }
    (( number >= 1 && number <= count )) || { echo "Invalid selection"; exit 1; }
    SELECTED_INDEX=$((number - 1))
    return
  fi

  local selected=0
  local key
  tput civis 2>/dev/null || true
  trap 'tput cnorm 2>/dev/null || true' RETURN

  while true; do
    clear
    echo "Available Synchy/freeSIEM exports"
    echo "Use up/down arrows, Enter to select, q to quit."
    echo

    for i in "${!PACKAGES[@]}"; do
      if [[ "$i" -eq "$selected" ]]; then
        printf " > %s | %s | %s\n" "${PACKAGES[$i]}" "${CREATED_AT[$i]}" "${HOME_URLS[$i]}"
      else
        printf "   %s | %s | %s\n" "${PACKAGES[$i]}" "${CREATED_AT[$i]}" "${HOME_URLS[$i]}"
      fi
    done

    IFS= read -rsn1 key || true
    case "$key" in
      $'\x1b')
        IFS= read -rsn2 -t 0.1 key || true
        case "$key" in
          "[A") (( selected > 0 )) && selected=$((selected - 1)) ;;
          "[B") (( selected < count - 1 )) && selected=$((selected + 1)) ;;
        esac
        ;;
      "")
        SELECTED_INDEX="$selected"
        return
        ;;
      q|Q)
        echo "Cancelled."
        exit 0
        ;;
    esac
  done
}

ensure_wp_config_for_ddev() {
  local docroot="$1"
  local db_prefix="$2"
  local wp_config="$docroot/wp-config.php"

  if [[ ! -f "$wp_config" && -f "$docroot/wp-config-sample.php" ]]; then
    cp "$docroot/wp-config-sample.php" "$wp_config"
  fi

  if [[ ! -f "$wp_config" ]]; then
    echo "Error: wp-config.php was not found and wp-config-sample.php was not available."
    exit 1
  fi

  python3 - "$wp_config" "$db_prefix" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
prefix = sys.argv[2] or "wp_"
contents = path.read_text()

replacements = {
    r"define\(\s*['\"]DB_NAME['\"]\s*,\s*['\"][^'\"]*['\"]\s*\)\s*;": "define('DB_NAME', 'db');",
    r"define\(\s*['\"]DB_USER['\"]\s*,\s*['\"][^'\"]*['\"]\s*\)\s*;": "define('DB_USER', 'db');",
    r"define\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"][^'\"]*['\"]\s*\)\s*;": "define('DB_PASSWORD', 'db');",
    r"define\(\s*['\"]DB_HOST['\"]\s*,\s*['\"][^'\"]*['\"]\s*\)\s*;": "define('DB_HOST', 'db');",
}

for pattern, replacement in replacements.items():
    contents = re.sub(pattern, replacement, contents)

contents = re.sub(
    r"\$table_prefix\s*=\s*['\"][^'\"]+['\"]\s*;",
    "$table_prefix = '" + prefix.replace("\\", "\\\\").replace("'", "\\'") + "';",
    contents,
)

path.write_text(contents)
PY
}

cleanup_local_runtime_files() {
  local docroot="$1"

  rm -rf "$docroot/wp-content/cache/"* 2>/dev/null || true
  rm -rf "$docroot/wp-content/uploads/cache/"* 2>/dev/null || true
  rm -rf "$docroot/wp-content/wflogs/"* 2>/dev/null || true
  rm -f "$docroot/wp-content/advanced-cache.php" 2>/dev/null || true
  rm -f "$docroot/wp-content/object-cache.php" 2>/dev/null || true
}

deactivate_broken_freesiem_plugin() {
  local docroot="$1"
  local plugin_dir="$docroot/wp-content/plugins/freesiem-sentinel"
  local runtime_file="$plugin_dir/includes/synchy/synchy-runtime.php"

  if [[ -d "$plugin_dir" && ! -f "$runtime_file" ]]; then
    echo "Deactivating freesiem-sentinel because its Synchy runtime file is missing..."
    ddev wp plugin deactivate freesiem-sentinel --skip-plugins --skip-themes || true
  fi
}

ensure_docker_ready() {
  if docker info >/dev/null 2>&1; then
    return 0
  fi

  if [[ "$OSTYPE" == "darwin"* ]] && command -v open >/dev/null 2>&1; then
    echo "Docker is not ready. Opening Docker Desktop..."
    open -a Docker || true
  else
    echo "Docker is not ready. Start Docker, then rerun this script."
    exit 1
  fi

  echo "Waiting for Docker Desktop..."
  for _ in {1..60}; do
    if docker info >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done

  echo "Docker did not become ready within 120 seconds. Start Docker, then rerun this script."
  exit 1
}

need_cmd ddev
need_cmd docker
need_cmd python3
need_cmd unzip
need_cmd rsync

BACKUP_ROWS=()
while IFS= read -r row; do
  BACKUP_ROWS+=("$row")
done < <(load_backups)

if [[ "${#BACKUP_ROWS[@]}" -eq 0 ]]; then
  echo "No complete Synchy/freeSIEM export triplets found in: $BACKUP_DIR"
  echo "Expected files: PACKAGE.zip, PACKAGE-installer.php, PACKAGE-manifest.json"
  exit 1
fi

MANIFESTS=()
ARCHIVES=()
INSTALLERS=()
PACKAGES=()
CREATED_AT=()
HOME_URLS=()
DB_PREFIXES=()
SUGGESTED_NAMES=()
SIZES=()

for row in "${BACKUP_ROWS[@]}"; do
  IFS=$'\t' read -r manifest archive installer package created home prefix suggested size <<< "$row"
  MANIFESTS+=("$manifest")
  ARCHIVES+=("$archive")
  INSTALLERS+=("$installer")
  PACKAGES+=("$package")
  CREATED_AT+=("$created")
  HOME_URLS+=("$home")
  DB_PREFIXES+=("$prefix")
  SUGGESTED_NAMES+=("$suggested")
  SIZES+=("$size")
done

SELECTED_INDEX=0
select_backup "${#PACKAGES[@]}"

MANIFEST="${MANIFESTS[$SELECTED_INDEX]}"
ARCHIVE="${ARCHIVES[$SELECTED_INDEX]}"
INSTALLER="${INSTALLERS[$SELECTED_INDEX]}"
PACKAGE="${PACKAGES[$SELECTED_INDEX]}"
CREATED="${CREATED_AT[$SELECTED_INDEX]}"
SOURCE_URL="${HOME_URLS[$SELECTED_INDEX]}"
DB_PREFIX="${DB_PREFIXES[$SELECTED_INDEX]}"
SUGGESTED_PROJECT="$(slugify "${SUGGESTED_NAMES[$SELECTED_INDEX]}")"

echo
echo "Selected backup:"
echo "  Package:      $PACKAGE"
echo "  Exported:     $CREATED"
echo "  Source:       $SOURCE_URL"
echo "  Archive:      $ARCHIVE"
echo

prompt PROJECT_NAME "New DDEV project/site folder name" "$SUGGESTED_PROJECT"
PROJECT_NAME="$(slugify "$PROJECT_NAME")"
prompt PHP_VERSION "PHP version" "$DEFAULT_PHP_VERSION"
prompt DB_VERSION "MariaDB version" "$DEFAULT_DB_VERSION"

PROJECT_PATH="$SITES_DIR/$PROJECT_NAME"
DOCROOT=""
DOCROOT_PATH="$PROJECT_PATH"

if [[ -e "$PROJECT_PATH" ]]; then
  echo "Error: $PROJECT_PATH already exists. Stopping without changes."
  exit 1
fi

if ! confirm_default_yes "Create $PROJECT_PATH from this export"; then
  echo "Cancelled."
  exit 0
fi

mkdir -p "$SITES_DIR"
mkdir "$PROJECT_PATH"

cd "$PROJECT_PATH"

echo "Configuring DDEV project..."
ddev config \
  --project-name="$PROJECT_NAME" \
  --project-type=wordpress \
  --docroot="$DOCROOT" \
  --php-version="$PHP_VERSION" \
  --database="mariadb:$DB_VERSION"

rm -rf ".synchy-import/extracted"
mkdir -p "$DOCROOT_PATH" ".synchy-import"

echo "Extracting archive..."
unzip -oq "$ARCHIVE" -d ".synchy-import/extracted"

SOURCE_PATH="$(choose_wordpress_source ".synchy-import/extracted")"

echo "Copying WordPress files into the site root..."
rsync -a --delete \
  --exclude='/synchy/' \
  --exclude='.synchy-import' \
  --exclude='.ddev' \
  --exclude='.git' \
  "$SOURCE_PATH/" "$DOCROOT_PATH/"

echo "Updating wp-config.php for DDEV..."
ensure_wp_config_for_ddev "$DOCROOT_PATH" "$DB_PREFIX"

ensure_docker_ready

echo "Starting DDEV..."
ddev start

if [[ -f ".synchy-import/extracted/synchy/database.sql" ]]; then
  echo "Importing bundled database..."
  ddev import-db --file=".synchy-import/extracted/synchy/database.sql"
else
  echo "No bundled database found at synchy/database.sql; skipping DB import."
fi

DDEV_URL="https://${PROJECT_NAME}.ddev.site"

deactivate_broken_freesiem_plugin "$DOCROOT_PATH"

if ddev wp core is-installed --skip-plugins --skip-themes >/dev/null 2>&1; then
  CURRENT_HOME="$(ddev wp option get home --skip-plugins --skip-themes 2>/dev/null || true)"
  CURRENT_SITEURL="$(ddev wp option get siteurl --skip-plugins --skip-themes 2>/dev/null || true)"

  echo "Rewriting WordPress URLs to $DDEV_URL ..."
  if [[ -n "$CURRENT_HOME" && "$CURRENT_HOME" != "$DDEV_URL" ]]; then
    ddev wp search-replace "$CURRENT_HOME" "$DDEV_URL" --all-tables --skip-columns=guid --skip-plugins --skip-themes || true
  fi
  if [[ -n "$CURRENT_SITEURL" && "$CURRENT_SITEURL" != "$CURRENT_HOME" && "$CURRENT_SITEURL" != "$DDEV_URL" ]]; then
    ddev wp search-replace "$CURRENT_SITEURL" "$DDEV_URL" --all-tables --skip-columns=guid --skip-plugins --skip-themes || true
  fi
  if [[ "$SOURCE_URL" != "Unknown source URL" && "$SOURCE_URL" != "$CURRENT_HOME" && "$SOURCE_URL" != "$CURRENT_SITEURL" ]]; then
    ddev wp search-replace "$SOURCE_URL" "$DDEV_URL" --all-tables --skip-columns=guid --skip-plugins --skip-themes || true
    ddev wp search-replace "${SOURCE_URL%/}" "$DDEV_URL" --all-tables --skip-columns=guid --skip-plugins --skip-themes || true
  fi

  ddev wp option update home "$DDEV_URL" --skip-plugins --skip-themes >/dev/null
  ddev wp option update siteurl "$DDEV_URL" --skip-plugins --skip-themes >/dev/null
  ddev wp rewrite flush --hard --skip-plugins --skip-themes || true
  ddev wp cache flush --skip-plugins --skip-themes || true
fi

echo "Cleaning cache/runtime files from restored copy..."
cleanup_local_runtime_files "$DOCROOT_PATH"

if confirm "Launch site in browser now"; then
  ddev launch
fi

echo
echo "Done."
echo "Project path: $PROJECT_PATH"
echo "Frontend:     $DDEV_URL"
echo "Admin:        $DDEV_URL/wp-admin"
