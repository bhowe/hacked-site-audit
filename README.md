# hacked-site-audit

Read-only SEO-spam / injected-link audit for WordPress sites over SSH. Runs a layered detection sweep (cloaked-fetch diff → file-system scan → database inspection → log review) against a target site and writes a timestamped report you can grep, diff, and commit.

Designed for the classic "pharma hack / Japanese keyword hack / Cyrillic SEO injection" class of compromises where the target site renders differently for Googlebot than for a normal browser.

## What's in here

| File | What it is |
|---|---|
| **`spam-link-audit.sh`** | Bash script that SSHes into a target and runs most of the checklist. Writes a timestamped report. Safe for production — never writes to the target. |
| **`spam-link-audit-checklist.md`** | The full checklist the script is based on. Covers stuff the script can't automate (server-level config, cPanel-specific paths, external scanner triage) so you can run those manually when the automated pass finds something. |

## Why

The web-based "Hacked Site Scanner" at [buildingbettersoftware.io/tools/hacked-site-scanner/](https://buildingbettersoftware.io/tools/hacked-site-scanner/) catches most cloaking-based SEO injections from the outside, but it can't look at files, the database, server crons, or logs. If that tool flags a site MEDIUM or worse — or if you want a full baseline sweep of a known-clean site — run this script over SSH instead.

## Requirements

- SSH access to the target (key-based)
- `curl`, `ssh`, `bash`, `python3` on your local box
- `wp-cli` installed on the target (optional — the script skips DB/WP checks without it, but file-system / cloaked-fetch / sitemap checks still run)

## Usage

```bash
./spam-link-audit.sh -h user@host -u https://site.com [-p public_html] [-k ~/.ssh/id_rsa] [-d 30] [-q]
```

| Flag | Meaning | Default |
|---|---|---|
| `-h` | SSH target | *required* |
| `-u` | Public URL (for cloaked-fetch diff + sitemap probe) | *required* |
| `-p` | Webroot path on the target | `public_html` |
| `-k` | SSH key file | *ssh default* |
| `-d` | Max age in days for the recently-modified-PHP sweep | `30` |
| `-q` | Quiet mode — write to the report file only, no stdout | *off* |

The script writes a report to `spam-audit-<host>-<timestamp>.txt` in the current directory.

## Example

```bash
./spam-link-audit.sh -h webadmin@203.0.113.10 -u https://example.com -d 14
```

## What it checks

Every check is read-only. Most sections can be jumped to individually in the output if you already know where to look.

1. **Cloaked-fetch diff** — fetches the target URL with a normal browser UA, a Googlebot UA, and a Google-referer, and diffs the outbound link sets. Any Googlebot-only or referer-only link is a smoking gun.
2. **File-system sweep** — recently-modified PHP (mtime window configurable), obfuscated-payload grep (eval+base64, preg_replace /e, create_function, classic webshell names), fake `wp-*.php` files outside the real core tree, PHP files in uploads/, mu-plugins listing, world-writable files.
3. **`.htaccess` / `.user.ini` cloaking** — recursive grep for `HTTP_USER_AGENT` / `HTTP_REFERER` / `auto_prepend_file` directives.
4. **WP core + plugin checksums** — `wp core verify-checksums` and `wp plugin verify-checksums --all`.
5. **Database checks** — spam keywords in `wp_posts`, payload markers in `wp_postmeta`, oversized autoloaded options, code-execution payloads in `wp_options`, admin user list (with a DB-vs-CLI count cross-check that catches invisible admins hidden via `pre_user_query` filter tampering), cron hooks, active plugins/themes.
6. **Sitemap / robots / feed** — robots.txt snapshot, sitemap URL count vs real post/page count. Sitemap >> real content means injected pages.
7. **Render-time outbound-link audit** — unique external domains visible to Googlebot.
8. **Priority summary** — a list of the exact signals you should investigate first if they appeared anywhere above.

## What it deliberately does NOT do

- **No writes to the target.** Ever. No cleanup, no quarantine, no file deletion. This is a detector, not a disinfector.
- **No root-required system checks.** Doesn't touch `/etc/crontab`, `/var/spool/cron/`, `php.ini`, or `authorized_keys` for other users. If you need those, you'll be on the box as root anyway — just grep them directly.
- **No external API calls.** No VirusTotal, no URLscan, no Google Safe Browsing. All of those are linked from the companion web tool.
- **No notifications.** Report goes to a file. Pipe it wherever you want.

## Companion web tool

For URL-only scanning without SSH access, use the public web-based version: https://buildingbettersoftware.io/tools/hacked-site-scanner/

It runs the cloaked-fetch diff, checks URLscan.io + Sucuri SiteCheck + Wayback Save-Page-Now, and asks Claude to triage the findings into a severity verdict. Less thorough than this script (no file-system / DB access) but takes 60 seconds and needs no setup.

## Fleet-wide use

If you run multiple WordPress sites, wrap it in a `for` loop:

```bash
for host in $(cat fleet.txt); do
  ./spam-link-audit.sh -h "$host" -u "https://${host#*@}" -q -d 14
done
```

Then `grep` all reports for the signals called out in section 8.

## License

MIT. No warranty. Run on sites you own or have authorization to audit.
