# hacked-site-audit

Read-only SEO-spam and injected-link audit for WordPress sites over SSH. Runs a layered sweep (cloaked-fetch diff, file-system scan, database inspection, log review) against a target site and writes a timestamped report you can grep, diff, and commit.

Built for the classic pharma hack, Japanese keyword hack, and Cyrillic SEO injection class of compromises. The kind where the site renders one way for Googlebot and another for a normal browser.

## What is in here

| File | What it does |
|---|---|
| **`spam-link-audit.sh`** | Bash script. SSHes into a target and runs most of the checklist. Writes a timestamped report. Safe on production. Never writes to the target. |
| **`spam-link-audit-checklist.md`** | The full checklist the script is based on. Includes the stuff the script cannot automate: server-level config, cPanel-specific paths, external scanner triage. Run those manually when the script flags something. |

## Why

The web-based [Hacked Site Scanner](https://buildingbettersoftware.io/tools/hacked-site-scanner/) catches most cloaking-based SEO injections from the outside. It cannot look at files, the database, server crons, or logs.

If that tool flags a site MEDIUM or worse, or if you want a full baseline sweep of a known-clean site, run this script over SSH instead.

## Requirements

- SSH access to the target (key-based).
- `curl`, `ssh`, `bash`, `python3` on your local box.
- `wp-cli` on the target (optional). Without it, the script skips DB and WP checks. File-system, cloaked-fetch, and sitemap checks still run.

## Usage

```bash
./spam-link-audit.sh -h user@host -u https://site.com [-p public_html] [-k ~/.ssh/id_rsa] [-d 30] [-q]
```

| Flag | Meaning | Default |
|---|---|---|
| `-h` | SSH target | required |
| `-u` | Public URL (for cloaked-fetch diff and sitemap probe) | required |
| `-p` | Webroot path on the target | `public_html` |
| `-k` | SSH key file | ssh default |
| `-d` | Max age in days for the modified-PHP sweep | `30` |
| `-q` | Quiet mode. Write only to the report file, no stdout. | off |

Report lands in `spam-audit-<host>-<timestamp>.txt` in the current directory.

## Example

```bash
./spam-link-audit.sh -h webadmin@203.0.113.10 -u https://example.com -d 14
```

## What it checks

Every check is read-only. Sections can be jumped to individually in the output if you know where to look.

1. **Cloaked-fetch diff.** Fetches the target URL with a normal browser UA, a Googlebot UA, and a Google-referer. Diffs the outbound link sets. Any Googlebot-only or referer-only link is a smoking gun.
2. **File-system sweep.** Recently-modified PHP (mtime window configurable), obfuscated-payload grep (eval+base64, preg_replace /e, create_function, classic webshell names), fake `wp-*.php` files outside the real core tree, PHP files in uploads/, mu-plugins listing, world-writable files.
3. **`.htaccess` and `.user.ini` cloaking.** Recursive grep for `HTTP_USER_AGENT`, `HTTP_REFERER`, and `auto_prepend_file` directives.
4. **WP core and plugin checksums.** `wp core verify-checksums` plus `wp plugin verify-checksums --all`.
5. **Database checks.** Spam keywords in `wp_posts`, payload markers in `wp_postmeta`, oversized autoloaded options, code-execution payloads in `wp_options`, admin user list with a DB-vs-CLI count cross-check (catches invisible admins hidden via `pre_user_query` filter tampering), cron hooks, active plugins and themes.
6. **Sitemap, robots, feed.** robots.txt snapshot, sitemap URL count vs real post/page count. A sitemap much bigger than the real content is injected pages.
7. **Render-time outbound-link audit.** Unique external domains visible to Googlebot.
8. **Priority summary.** A list of the exact signals you should investigate first if they showed up anywhere above.

## What it deliberately does not do

- **No writes to the target.** Ever. No cleanup, no quarantine, no file deletion. This is a detector, not a disinfector.
- **No root-required system checks.** Does not touch `/etc/crontab`, `/var/spool/cron/`, `php.ini`, or `authorized_keys` for other users. If you need those, you are on the box as root anyway. Just grep them directly.
- **No external API calls.** No VirusTotal, no URLscan, no Google Safe Browsing. Those are linked from the companion web tool.
- **No notifications.** Report goes to a file. Pipe it wherever you want.

## Companion web tool

For URL-only scanning without SSH access, use the public web version: [buildingbettersoftware.io/tools/hacked-site-scanner](https://buildingbettersoftware.io/tools/hacked-site-scanner/).

It runs the cloaked-fetch diff, queries URLscan.io and Sucuri SiteCheck and Wayback Save-Page-Now, and asks Claude to rank the findings into a severity verdict. Less thorough than this script (no file-system or DB access) but takes 60 seconds and needs no setup.

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
