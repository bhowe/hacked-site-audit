#!/usr/bin/env bash
#
# spam-link-audit.sh — read-only SEO-spam / injected-link audit for WordPress sites.
#
# Runs the checklist from spam-link-audit-checklist.md against a target site over SSH.
# Does NOT modify anything on the target — safe to run on production.
#
# Usage:
#   ./spam-link-audit.sh -h user@host -u https://site.com [-p public_html] [-k ~/.ssh/id_rsa]
#
# Output: prints to stdout AND writes a timestamped report next to this script.
#
# Sections:
#   1. Cloaked-fetch diff (local — needs curl)
#   2. File-system sweep over SSH (mtime, obfuscation, fake WP files, uploads, mu-plugins)
#   3. .htaccess / .user.ini cloaking
#   4. wp core & plugin checksums
#   5. Database content + options + cron + users (WP-CLI)
#   6. Sitemap / robots / feed audit
#   7. Render-time outbound-link audit (Googlebot UA)
#   8. Priority summary
#
# Flags:
#   -h  SSH target  (required)        e.g. user@host
#   -u  Public URL  (required)        e.g. https://site.com
#   -p  Web root    (default: public_html)
#   -k  SSH key     (optional)        e.g. ~/.ssh/id_rsa
#   -d  Max mtime days for file sweep (default: 30)
#   -q  Quiet mode — report file only, no stdout

set -u

SSH_HOST=""
PUBLIC_URL=""
WEB_ROOT="public_html"
SSH_KEY=""
MTIME_DAYS=30
QUIET=0

while getopts "h:u:p:k:d:q" opt; do
  case "$opt" in
    h) SSH_HOST="$OPTARG" ;;
    u) PUBLIC_URL="$OPTARG" ;;
    p) WEB_ROOT="$OPTARG" ;;
    k) SSH_KEY="$OPTARG" ;;
    d) MTIME_DAYS="$OPTARG" ;;
    q) QUIET=1 ;;
    *) exit 2 ;;
  esac
done

if [[ -z "$SSH_HOST" || -z "$PUBLIC_URL" ]]; then
  echo "Usage: $0 -h user@host -u https://site.com [-p public_html] [-k keyfile] [-d days] [-q]" >&2
  exit 2
fi

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new)
if [[ -n "$SSH_KEY" ]]; then
  SSH_OPTS+=(-i "$SSH_KEY")
fi

TS=$(date +%Y%m%d-%H%M%S)
SAFE_HOST=$(echo "$SSH_HOST" | tr -c 'A-Za-z0-9' '_')
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPORT="$SCRIPT_DIR/spam-audit-${SAFE_HOST}-${TS}.txt"

# --- output helpers ---------------------------------------------------------

say()   { if [[ $QUIET -eq 0 ]]; then echo "$@" | tee -a "$REPORT"; else echo "$@" >> "$REPORT"; fi; }
header(){ say ""; say "============================================================"; say "=== $*"; say "============================================================"; }
sub()   { say ""; say "--- $* ---"; }
note()  { say "    $*"; }
fail()  { say "    !! $*"; }

# --- SSH runner (read-only, bounded output) ---------------------------------

rmt() {
  # shellcheck disable=SC2029
  ssh "${SSH_OPTS[@]}" "$SSH_HOST" "$1" 2>&1
}

# --- preflight --------------------------------------------------------------

header "Target: $SSH_HOST  ($PUBLIC_URL)  web_root=$WEB_ROOT  mtime-days=$MTIME_DAYS"
say "Report: $REPORT"
say "Run time: $(date)"

sub "Preflight: SSH reachable?"
if rmt "echo ok" | grep -q '^ok$'; then
  note "SSH OK"
else
  fail "Cannot SSH to $SSH_HOST — bailing."
  exit 1
fi

sub "Preflight: wp-cli available?"
WP_VER=$(rmt "cd $WEB_ROOT && wp core version 2>/dev/null")
if [[ -n "$WP_VER" ]]; then
  note "wp-cli OK — WordPress $WP_VER"
  HAVE_WP=1
else
  fail "wp-cli not available or not a WP site in $WEB_ROOT — DB/WP checks will be skipped."
  HAVE_WP=0
fi

# ============================================================================
# 1. Cloaked-fetch diff (LOCAL — compares browser UA vs Googlebot UA)
# ============================================================================
header "1. Cloaked-fetch diff (browser UA vs Googlebot)"

BROWSER_UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
GOOGLEBOT_UA="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if curl -sf --max-time 30 -A "$BROWSER_UA" "$PUBLIC_URL" -o "$TMP/browser.html" \
   && curl -sf --max-time 30 -A "$GOOGLEBOT_UA" "$PUBLIC_URL" -o "$TMP/googlebot.html"; then

  grep -oE 'href="[^"]+"' "$TMP/browser.html"   | sort -u > "$TMP/browser.links"
  grep -oE 'href="[^"]+"' "$TMP/googlebot.html" | sort -u > "$TMP/googlebot.links"

  BROWSER_LINKS=$(wc -l < "$TMP/browser.links" | tr -d ' ')
  GBOT_LINKS=$(wc -l < "$TMP/googlebot.links" | tr -d ' ')
  note "Links visible to browser: $BROWSER_LINKS"
  note "Links visible to Googlebot: $GBOT_LINKS"

  # Only in Googlebot view (the danger set)
  GBOT_ONLY=$(comm -13 "$TMP/browser.links" "$TMP/googlebot.links")
  if [[ -n "$GBOT_ONLY" ]]; then
    fail "Googlebot-only links found (CLOAKING SUSPECTED):"
    say "$GBOT_ONLY" | sed 's/^/      /'
  else
    note "No Googlebot-only links — no cloaking signal from this page."
  fi

  # Google-referer variant
  if curl -sf --max-time 30 -A "$BROWSER_UA" -e "https://www.google.com/search?q=$PUBLIC_URL" "$PUBLIC_URL" -o "$TMP/goog-ref.html"; then
    grep -oE 'href="[^"]+"' "$TMP/goog-ref.html" | sort -u > "$TMP/goog-ref.links"
    REF_ONLY=$(comm -13 "$TMP/browser.links" "$TMP/goog-ref.links")
    if [[ -n "$REF_ONLY" ]]; then
      fail "Google-referer-only links found (REFERER CLOAKING SUSPECTED):"
      say "$REF_ONLY" | sed 's/^/      /'
    else
      note "No Google-referer-only links."
    fi
  fi

  # Outbound domains from Googlebot view — pivot points
  sub "Outbound domains (Googlebot view)"
  HOST_ONLY=$(echo "$PUBLIC_URL" | sed -E 's#^https?://([^/]+).*#\1#')
  grep -oE 'href="https?://[^"/]+' "$TMP/googlebot.html" \
    | sed -E 's#^href="https?://##' \
    | sort -u \
    | grep -v "^$HOST_ONLY$" \
    | head -50 \
    | sed 's/^/      /' | tee -a "$REPORT"
else
  fail "curl fetch failed — can't run cloaked-fetch diff."
fi

# ============================================================================
# 2. File-system sweep over SSH
# ============================================================================
header "2. File-system sweep (SSH)"

sub "2a. Recently-modified PHP (last $MTIME_DAYS days)"
rmt "find $WEB_ROOT -name '*.php' -mtime -$MTIME_DAYS -printf '%T+ %p\n' 2>/dev/null | sort | tail -50" | sed 's/^/    /' | tee -a "$REPORT"

sub "2b. Obfuscated payload grep (eval/base64/gzinflate/create_function/webshells)"
rmt "cd $WEB_ROOT && grep -rnlE 'eval\\s*\\(\\s*(base64_decode|gzinflate|gzuncompress|str_rot13)' --include='*.php' . 2>/dev/null | head -30" | sed 's/^/    /' | tee -a "$REPORT"
rmt "cd $WEB_ROOT && grep -rnlE 'preg_replace\\s*\\(\\s*[\"'\\''].*/e[\"'\\'']' --include='*.php' . 2>/dev/null | head -20" | sed 's/^/    /' | tee -a "$REPORT"
rmt "cd $WEB_ROOT && grep -rnlE 'create_function\\s*\\(' --include='*.php' . 2>/dev/null | head -20" | sed 's/^/    /' | tee -a "$REPORT"
rmt "cd $WEB_ROOT && grep -rnlE 'FilesMan|WSO|c99|r57|b374k' --include='*.php' . 2>/dev/null | head -20" | sed 's/^/    /' | tee -a "$REPORT"
rmt "cd $WEB_ROOT && grep -rnl 'auto_prepend_file' --include='*.php' --include='.htaccess' --include='.user.ini' . 2>/dev/null | head -20" | sed 's/^/    /' | tee -a "$REPORT"

sub "2c. Fake WP-core files outside the real tree"
rmt "find $WEB_ROOT -name 'wp-*.php' -not -path '*/wp-admin/*' -not -path '*/wp-includes/*' -not -path '*/wp-content/plugins/*' 2>/dev/null" | sed 's/^/    /' | tee -a "$REPORT"

sub "2d. PHP in uploads dir (should be empty)"
rmt "find $WEB_ROOT/wp-content/uploads \\( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \\) 2>/dev/null" | sed 's/^/    /' | tee -a "$REPORT"

sub "2e. mu-plugins listing"
rmt "ls -la $WEB_ROOT/wp-content/mu-plugins/ 2>/dev/null" | sed 's/^/    /' | tee -a "$REPORT"

sub "2f. World-writable files"
rmt "find $WEB_ROOT -type f -perm /o=w 2>/dev/null | head -30" | sed 's/^/    /' | tee -a "$REPORT"

# ============================================================================
# 3. .htaccess / .user.ini cloaking
# ============================================================================
header "3. .htaccess / .user.ini cloaking rules"

sub "3a. .htaccess files containing UA/Referer/auto_prepend rules"
rmt "find $WEB_ROOT -name '.htaccess' -exec grep -lE 'HTTP_USER_AGENT|HTTP_REFERER|RewriteRule.*\\[R=301|auto_prepend' {} \\; 2>/dev/null" | sed 's/^/    /' | tee -a "$REPORT"

sub "3b. .user.ini / php.ini dropped by user"
rmt "find $WEB_ROOT -name '.user.ini' -o -name 'php.ini' 2>/dev/null" | sed 's/^/    /' | tee -a "$REPORT"

# ============================================================================
# 4. WP core + plugin checksum verification
# ============================================================================
if [[ $HAVE_WP -eq 1 ]]; then
  header "4. WP core + plugin checksum verification"

  sub "4a. wp core verify-checksums"
  rmt "cd $WEB_ROOT && wp core verify-checksums 2>&1 | tail -40" | sed 's/^/    /' | tee -a "$REPORT"

  sub "4b. wp plugin verify-checksums --all"
  rmt "cd $WEB_ROOT && wp plugin verify-checksums --all 2>&1 | tail -60" | sed 's/^/    /' | tee -a "$REPORT"
fi

# ============================================================================
# 5. Database checks (WP-CLI)
# ============================================================================
if [[ $HAVE_WP -eq 1 ]]; then
  header "5. Database checks"

  sub "5a. Posts with spam keywords or hidden-content CSS"
  rmt "cd $WEB_ROOT && wp db query \"SELECT ID, post_status, LEFT(post_title,80) AS title FROM wp_posts WHERE post_content REGEXP '(viagra|cialis|casino|replica|xanax|payday|<script|display:\\\\s*none|visibility:\\\\s*hidden|position:\\\\s*absolute.*-9999)' LIMIT 50;\" 2>&1" | sed 's/^/    /' | tee -a "$REPORT"

  sub "5b. Postmeta with suspicious HTML/JS/Russian-TLD links"
  rmt "cd $WEB_ROOT && wp db query \"SELECT post_id, meta_key, LEFT(meta_value,200) AS sample FROM wp_postmeta WHERE meta_value REGEXP '(<script|eval\\\\(|base64_decode|href=.https?://[^.]+\\\\.(ru|cn|top|xyz|tk|ml|ga|cf))' LIMIT 50;\" 2>&1" | sed 's/^/    /' | tee -a "$REPORT"

  sub "5c. Oversized autoloaded options"
  rmt "cd $WEB_ROOT && wp option list --autoload=on --fields=option_name,size_bytes --format=csv 2>/dev/null | sort -t, -k2 -nr | head -20" | sed 's/^/    /' | tee -a "$REPORT"

  sub "5d. Options with code-execution payloads"
  rmt "cd $WEB_ROOT && wp db query \"SELECT option_id, option_name FROM wp_options WHERE option_value REGEXP '(eval\\\\(|base64_decode|gzinflate|<script|auto_prepend)' LIMIT 50;\" 2>&1" | sed 's/^/    /' | tee -a "$REPORT"

  sub "5e. Admin user list (UI)"
  rmt "cd $WEB_ROOT && wp user list --role=administrator --fields=ID,user_login,user_email,user_registered 2>&1" | sed 's/^/    /' | tee -a "$REPORT"

  sub "5f. Admin user count — DB raw vs wp-cli (mismatch = invisible users)"
  UI_ADMIN_COUNT=$(rmt "cd $WEB_ROOT && wp user list --role=administrator --format=count 2>/dev/null" | tr -d '[:space:]')
  DB_ADMIN_COUNT=$(rmt "cd $WEB_ROOT && wp db query \"SELECT COUNT(DISTINCT user_id) FROM wp_usermeta WHERE meta_key='wp_capabilities' AND meta_value LIKE '%administrator%';\" --skip-column-names 2>/dev/null" | tr -d '[:space:]')
  note "wp-cli says: $UI_ADMIN_COUNT administrators"
  note "DB says:     $DB_ADMIN_COUNT administrators"
  if [[ -n "$UI_ADMIN_COUNT" && -n "$DB_ADMIN_COUNT" && "$UI_ADMIN_COUNT" != "$DB_ADMIN_COUNT" ]]; then
    fail "MISMATCH — invisible admin users likely present. Look for pre_user_query filter tampering."
  fi

  sub "5g. Scheduled cron hooks"
  rmt "cd $WEB_ROOT && wp cron event list --fields=hook,next_run_relative,recurrence --format=table 2>&1 | head -60" | sed 's/^/    /' | tee -a "$REPORT"

  sub "5h. Active plugins"
  rmt "cd $WEB_ROOT && wp plugin list --status=active --fields=name,version,status 2>&1" | sed 's/^/    /' | tee -a "$REPORT"

  sub "5i. Active theme"
  rmt "cd $WEB_ROOT && wp theme list --status=active --fields=name,version,update 2>&1" | sed 's/^/    /' | tee -a "$REPORT"
fi

# ============================================================================
# 6. Sitemap / robots / feed audit
# ============================================================================
header "6. Sitemap / robots / feed audit"

sub "6a. robots.txt"
curl -sf --max-time 15 "$PUBLIC_URL/robots.txt" | head -40 | sed 's/^/    /' | tee -a "$REPORT"

sub "6b. Sitemap URL count (wp-sitemap.xml | sitemap.xml | sitemap_index.xml)"
for s in wp-sitemap.xml sitemap.xml sitemap_index.xml; do
  CODE=$(curl -so /tmp/.sm -w "%{http_code}" --max-time 15 "$PUBLIC_URL/$s")
  if [[ "$CODE" == "200" ]]; then
    COUNT=$(grep -oE "<loc>[^<]+" /tmp/.sm | wc -l | tr -d ' ')
    note "$s → HTTP 200, <loc> count: $COUNT"
  fi
done

if [[ $HAVE_WP -eq 1 ]]; then
  REAL_POSTS=$(rmt "cd $WEB_ROOT && wp post list --post_type=post --format=count 2>/dev/null" | tr -d ' ')
  REAL_PAGES=$(rmt "cd $WEB_ROOT && wp post list --post_type=page --format=count 2>/dev/null" | tr -d ' ')
  note "Real post count: $REAL_POSTS   Real page count: $REAL_PAGES"
fi

# ============================================================================
# 7. Render-time outbound-link audit (Googlebot UA)
# ============================================================================
header "7. Render-time outbound-link audit (Googlebot UA)"

if [[ -f "$TMP/googlebot.html" ]]; then
  sub "Unique outbound domains in Googlebot-view of homepage"
  HOST_ONLY=$(echo "$PUBLIC_URL" | sed -E 's#^https?://([^/]+).*#\1#')
  python3 - <<PY | sed 's/^/    /' | tee -a "$REPORT"
import re,sys
html = open("$TMP/googlebot.html").read()
links = set(re.findall(r'href="(https?://[^"]+)"', html))
domains = sorted({re.sub(r'^https?://', '', u).split('/')[0] for u in links})
own = "$HOST_ONLY"
external = [d for d in domains if d != own and not d.endswith('.' + own)]
for d in external:
    print(d)
PY
else
  note "(skipped — no Googlebot fetch available)"
fi

# ============================================================================
# 8. Priority summary
# ============================================================================
header "8. Summary"

say "If you see ANY of these in the sections above, investigate first:"
say "  - Googlebot-only or Google-referer-only links in section 1"
say "  - Files in section 2b (obfuscated payload grep)"
say "  - Fake wp-*.php files in section 2c"
say "  - PHP files anywhere under uploads/ in section 2d"
say "  - Non-empty mu-plugins listing in section 2e that you didn't create"
say "  - Any hit in section 3a (cloaking .htaccess rules)"
say "  - checksum failures in section 4"
say "  - ANY hits in 5a, 5b, 5d (DB content with spam / script / payload markers)"
say "  - Admin-count mismatch in 5f (invisible users)"
say "  - Unknown cron hooks in 5g"
say "  - Sitemap URL count >> real post+page count in section 6"
say "  - Unfamiliar outbound domains in section 7"
say ""
say "Next steps if compromised:"
say "  1. Do NOT clean yet. First kill the re-injection vector (section 5g + mu-plugins)."
say "  2. Take a forensic tarball: tar czf /tmp/forensic-\$(date +%F).tar.gz $WEB_ROOT"
say "  3. Rotate ALL secrets: WP admin, DB, SFTP/SSH, API keys in wp_options."
say "  4. Then clean content, then purge Breeze / edge cache, then Search Console re-inspection."
say ""
say "Report saved to: $REPORT"
