# Injected-Link / SEO-Spam Hack Audit Checklist

A layered detection playbook for WordPress sites suspected of having injected outbound links (classic pharma / casino / replica / Japanese-keyword / Cyrillic-SEO hacks). Ordered so you can run top-to-bottom or jump straight to the most-likely hit.

Assumes SSH + WP-CLI access. Fleet-friendly — most commands loop cleanly over a list of sites.

---

## 1. Quick triage (5–10 min) — catches ~80% of cases

### 1a. Cloaked-fetch diff

The single most important test. Most SEO injections only show for Googlebot or for visitors coming from a Google referer, so a normal browser view will look fine while the SERP is full of spam.

```bash
# Real browser view
curl -sA "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" https://SITE/ -o /tmp/ua-browser.html

# Googlebot view — this is where the spam usually lives
curl -sA "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" https://SITE/ -o /tmp/ua-googlebot.html

# Google-referer view
curl -s -e "https://www.google.com/search?q=SITE" https://SITE/ -o /tmp/ref-google.html

diff <(grep -oE 'href="[^"]+"' /tmp/ua-browser.html  | sort -u) \
     <(grep -oE 'href="[^"]+"' /tmp/ua-googlebot.html | sort -u)
```

If the Googlebot version has links the browser version doesn't, you're done looking — that's the smoking gun. Note the rogue domains and use them as pivot points for the rest of the audit.

### 1b. Google SERP check (browser)

```
site:SITE.com
site:SITE.com viagra OR casino OR cialis OR replica OR loans OR porn OR 代 OR かつら
site:SITE.com inurl:.php?
site:SITE.com filetype:pdf          # PDF-based injection is common
```

Then in **Google Search Console**:
- Security Issues
- Manual Actions
- Pages → Indexed (look for URLs you didn't create)
- Coverage → "Indexed, not submitted in sitemap"

Also hit **Bing Webmaster Tools** and **Yandex Webmaster** — Yandex often still indexes spam that Google has already dropped.

---

## 2. File system — where injections hide

### 2a. Recently-modified PHP ("what changed lately")

```bash
find /home/USER/public_html -name "*.php" -mtime -30 -printf "%T+ %p\n" | sort | tail -50
find /home/USER/public_html -name "*.php" -mtime -7  -printf "%T+ %p\n" | sort
```

### 2b. Obfuscated payload grep

These patterns are 99% malware. If you get hits, read them before deleting.

```bash
cd /home/USER/public_html
grep -rnlE "eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)" --include="*.php" .
grep -rnlE "(eval|assert)\s*\(\s*\\\$"                                    --include="*.php" .
grep -rnlE "preg_replace\s*\(\s*['\"].*\/e['\"]"                          --include="*.php" .   # preg_replace /e modifier
grep -rnlE "\\\$GLOBALS\[[\"']\\\\x"                                      --include="*.php" .   # hex-obfuscated globals
grep -rnlE "create_function\s*\("                                         --include="*.php" .
grep -rnl  "auto_prepend_file"        --include="*.php" --include=".htaccess" --include=".user.ini" .
grep -rnlE "FilesMan|WSO|c99|r57|b374k"                                   --include="*.php" .   # classic webshells
```

### 2c. Fake-WP-file hunt

Attackers love dropping files named like WP core (`wp-cahce.php`, `wp-includes-core.php`, `wp-login-old.php`):

```bash
find public_html -name "wp-*.php" \
  -not -path "*/wp-admin/*" \
  -not -path "*/wp-includes/*" \
  -not -path "*/wp-content/plugins/*/wp-*.php"
# Anything outside the real wp-*.php set is suspect.
```

### 2d. Uploads dir should have zero PHP

```bash
find public_html/wp-content/uploads -name "*.php" -o -name "*.phtml" -o -name "*.phar"
```

### 2e. mu-plugins hijack

Easiest place to run code on every request with zero UI presence. There should be nothing here (or at most things you put there yourself):

```bash
ls -la public_html/wp-content/mu-plugins/
```

### 2f. Theme & plugin tamper

```bash
wp core verify-checksums
wp plugin verify-checksums --all
# Themes don't have official checksums. Diff against a clean copy if you have one:
diff -r public_html/wp-content/themes/THEME /path/to/clean/THEME
```

### 2g. `.htaccess` cloaking rules

Check **every** `.htaccess`, not just the root — attackers drop cloaking rules in subdirs:

```bash
find public_html -name ".htaccess" -exec grep -lE "HTTP_USER_AGENT|HTTP_REFERER|RewriteRule.*\[R=301|auto_prepend" {} \;
```

### 2h. `.user.ini` / `php.ini` injection

```bash
find public_html -name ".user.ini" -o -name "php.ini"
```

### 2i. Hidden files & weird permissions

```bash
find public_html -type f -name ".*" ! -name ".htaccess" ! -name ".gitignore" ! -name ".DS_Store"
find public_html -type f -perm /o=w                                    # world-writable
find public_html -type f -name "*.php" -newer /tmp/reference_file      # newer than a baseline
```

---

## 3. Database — the other half of injection attacks

### 3a. Content scan (spam keywords + common injection markers)

```bash
wp db query "SELECT ID, post_status, post_title FROM wp_posts
  WHERE post_content REGEXP '(viagra|cialis|casino|replica|xanax|payday|essay writing|порно|代孕|かつら|바카라|<script|display:\\s*none|visibility:\\s*hidden|position:\\s*absolute.*-9999)'
  LIMIT 100;"

wp db query "SELECT post_id, meta_key, LEFT(meta_value,200) FROM wp_postmeta
  WHERE meta_value REGEXP '(<script|eval\\(|base64_decode|href=.https?://[^.]+\\.(ru|cn|top|xyz|tk|ml|ga|cf))'
  LIMIT 100;"
```

### 3b. `wp_options` payload scan

Hackers love stuffing base64 blobs into serialized options — the option loads autoload, executes, and no file on disk is touched.

```bash
wp db query "SELECT option_id, option_name, LENGTH(option_value) FROM wp_options
  WHERE LENGTH(option_value) > 50000
  ORDER BY LENGTH(option_value) DESC LIMIT 20;"

wp db query "SELECT option_id, option_name FROM wp_options
  WHERE option_value REGEXP '(eval\\(|base64_decode|gzinflate|<script|auto_prepend)'
  LIMIT 50;"
```

### 3c. `wp_options` autoload junk

```bash
wp option list --autoload=on --fields=option_name,size_bytes --format=table | sort -k2 -nr | head -30
```

### 3d. Cron hijack

Scheduled jobs that **regenerate injections after you clean them** — always find these before starting cleanup or the spam will come back.

```bash
wp cron event list
wp db query "SELECT option_value FROM wp_options WHERE option_name='cron';" | \
  php -r '$c=unserialize(trim(stream_get_contents(STDIN))); foreach($c as $ts=>$hooks){if(!is_array($hooks))continue; foreach($hooks as $h=>$_){ echo date("c",$ts)." $h\n";}}' | sort -u
```

Look for hooks you don't recognize. Diff against a clean reference site if you have one.

### 3e. Rogue admin users

```bash
wp user list --role=administrator --fields=ID,user_login,user_email,user_registered
wp db query "SELECT user_id, meta_key, meta_value FROM wp_usermeta
  WHERE meta_key='wp_capabilities' AND meta_value LIKE '%administrator%';"
```

Compare counts. If the DB has more admins than `wp user list` returns, you have **invisible users** (hidden via `pre_user_query` filter tampering in a rogue plugin). That's a strong compromise signal — time to look for the plugin doing the hiding.

### 3f. Search for specific outbound domains

Replace with whatever spam domains you saw in step 1a:

```bash
wp db query "SELECT ID, post_title FROM wp_posts
  WHERE post_content LIKE '%suspicious-domain.ru%' OR post_content LIKE '%spammy.xyz%';"

wp db query "SELECT option_id, option_name FROM wp_options
  WHERE option_value LIKE '%suspicious-domain.ru%';"
```

---

## 4. Server config — below WordPress

### 4a. Server crons (not WP crons — actual cPanel/system crons)

```bash
crontab -l                                    # user crontab
cat /etc/crontab /etc/cron.d/* 2>/dev/null    # if root
ls -la /var/spool/cron/                       # all user crontabs (root)
```

### 4b. PHP config injection

```bash
php --ini
grep -E "auto_prepend|auto_append|disable_functions" /opt/cpanel/ea-php*/root/etc/php.ini 2>/dev/null
find / -name ".user.ini" 2>/dev/null
```

### 4c. SSH / authorized_keys backdoor

```bash
cat ~/.ssh/authorized_keys
ls -la ~/.ssh/
find / -name "authorized_keys" 2>/dev/null
```

### 4d. Cron-based file touchers

An attacker may re-inject on a schedule. Look for any core file newer than the WP release that owns it:

```bash
find public_html/wp-admin public_html/wp-includes -name "*.php" -newer public_html/wp-settings.php
```

### 4e. cPanel-level check (if cPanel box)

```bash
ls -la ~/etc/                       # weird email accounts can be exfil backdoors
grep -r "forward" ~/etc/ 2>/dev/null
cat ~/.cpanel/datastore/* 2>/dev/null
```

---

## 5. Access logs — who's writing to the site

Log path varies. On cPanel it's typically `~/access-logs/SITE` or `/etc/apache2/logs/domlogs/USER`. Set it once and reuse:

```bash
LOG=~/access-logs/SITE
```

### 5a. POST hits to injection targets

```bash
grep -E "POST /wp-admin/admin-ajax.php|POST /xmlrpc.php|POST /wp-login.php|POST /wp-content/uploads/" $LOG | \
  awk '{print $1}' | sort | uniq -c | sort -rn | head -20
```

### 5b. Requests to suspicious paths

```bash
grep -vE "wp-admin|wp-includes|wp-content|\.css|\.js|\.png|\.jpg|\.webp|\.svg|\.ico|\.woff|\.mp4|xmlrpc|favicon|robots|sitemap" $LOG | \
  awk '{print $7}' | sort -u | less
```

### 5c. Bot activity on non-existent paths

Injected pages often get crawled heavily because the attacker submits a rogue sitemap. Look for Googlebot hitting paths that shouldn't exist:

```bash
grep -iE "Googlebot|Bingbot|YandexBot" $LOG | awk '{print $7}' | sort | uniq -c | sort -rn | head -30
```

### 5d. Sudden traffic spikes to individual pages

```bash
awk '{print $7}' $LOG | sort | uniq -c | sort -rn | head -30
```

---

## 6. External scanners (parallel, ~free)

Run these in a separate browser tab while the CLI sweep runs:

- **Sucuri SiteCheck** — https://sitecheck.sucuri.net/results/SITE
- **Google Safe Browsing status** — https://transparencyreport.google.com/safe-browsing/search?url=SITE
- **VirusTotal URL** — https://www.virustotal.com/gui/home/url
- **Quttera** — https://quttera.com/
- **URLscan.io** — `https://urlscan.io/search/#domain:SITE` — shows past scans + extracted outbound links
- **Wayback Machine** — compare current SERP snippets vs historical snapshots
- **archive.today** — alternate snapshot source, sometimes catches cloaked content
- **Wordfence free scan** (if installed) — `wp wordfence scan` via WP-CLI

---

## 7. Sitemap / robots / feed checks (often overlooked)

```bash
curl -s https://SITE/sitemap.xml       | grep -oE "<loc>[^<]+" | sort -u
curl -s https://SITE/sitemap_index.xml | grep -oE "<loc>[^<]+"
curl -s https://SITE/wp-sitemap.xml
curl -s https://SITE/robots.txt
curl -s https://SITE/feed/             | grep -oE "<link>[^<]+"
```

Compare against your real page count: `wp post list --post_type=page --format=count`. Any mismatch = injected content somewhere.

---

## 8. Render-time outbound-link audit

Catches server-side injection that file grep misses (e.g., an `add_filter('the_content', …)` hook in a rogue plugin or DB option):

```bash
# Every outbound link the homepage shows to Google
curl -sA "Googlebot" https://SITE/ | \
  python3 -c "import sys,re; [print(u) for u in set(re.findall(r'href=\"(https?://[^\"]+)\"', sys.stdin.read()))]" | \
  grep -v "SITE" | sort -u
```

Repeat for a handful of interior pages, `/feed/`, `/sitemap.xml`, `/wp-json/wp/v2/posts`. Domains you don't recognize become your pivot points.

---

## Fleet-wide application

Most of this becomes a one-liner over a site list. On the MainWP dashboard box or any machine with SSH keys to the fleet:

```bash
for site in $(cat fleet.txt); do
  echo "=== $site ==="
  ssh $site 'cd public_html && grep -rnlE "eval\s*\(\s*base64_decode|auto_prepend_file" --include="*.php" . 2>/dev/null | head -5'
done
```

Same pattern applies to: recent-mtime sweep, `wp core verify-checksums`, rogue-admin check, cloaked-fetch diff.

---

## Priority order (if you're under time pressure)

1. **Cloaked-fetch diff** (Googlebot UA) — fastest path to proof, tells you the attacker's domains
2. `wp core verify-checksums` + `wp plugin verify-checksums --all`
3. Recently-modified PHP sweep (`find -mtime -30`)
4. `wp_options` + `wp_posts` regex scan for spam keywords and base64
5. `.htaccess` cloaking rule grep
6. `wp_options` cron inspection — **kill re-injection crons before cleaning**
7. Rogue admin + invisible user check
8. Access log review for POST hits / Googlebot anomalies

---

## Cleanup gotchas (notes for when you move from detect → clean)

- **Kill the re-injection vector before cleaning content.** Cleanup is pointless if a cron or mu-plugin rewrites the damage in 10 minutes.
- **Rotate all secrets** after any confirmed compromise: WP admin passwords, SFTP/SSH, DB, and any API keys stored in `wp_options` (SMTP, Stripe, etc.). Assume the attacker has exfiltrated anything in the DB.
- **Purge every cache layer** after cleanup: object cache, page cache (Breeze / Rocket / Cloudflare), and ask Google to re-crawl via Search Console's URL inspection tool.
- **Check Postmark / SMTP logs** for outbound spam mail — SEO injection and mailer abuse are usually the same attacker.
- **Regenerate `.htaccess` from scratch** rather than trying to diff a tampered one.
- **Take a forensic copy** (`tar czf /tmp/forensic-$(date +%F).tar.gz public_html`) before deleting anything. Future-you will want the IoCs.

