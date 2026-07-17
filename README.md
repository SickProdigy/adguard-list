# SickProdigy Adguard Filter Lists

My personal AdGuard blocker/unblocker lists.

## Lists

- `assets/Filter-1.txt`: AdGuard Home / DNS filtering rules. Use this for network-wide blocking in AdGuard Home or similar DNS blockers.
- `assets/Filter-2.txt`: Browser add-on rules. Use this in AdGuard Browser Extension, uBlock Origin, or another browser/content blocker that supports URL parameter removal, cosmetic filtering, and URL/path rules.

## Installation

### AdGuard Home / DNS filters

Add this as a custom DNS blocklist:

https://gitea.sickgaming.net/sickprodigy/adguard-list/raw/branch/main/assets/Filter-1.txt

This list is mainly to block missing trackers and bad actors that are still able to load on my network. Use it alongside other DNS filters. It also unblocks a few domains to keep sites usable, like `t.co`, `error-report.com`, and `html-load.com`.

### Browser add-on filters

Add this as a custom browser/content filter:

https://gitea.sickgaming.net/sickprodigy/adguard-list/raw/branch/main/assets/Filter-2.txt

This list contains rules that AdGuard Home cannot apply, including `$removeparam`, cosmetic selectors like `##`, and URL/path/script rules. These need a browser extension or local client that can see full HTTPS URLs and page elements.

## Notes

A lot of time for paywall sites you can just disable JavaScript and many functions will disappear. Other times you will need userscripts; magnolia1234 has explained it well in their scripts if interested.

Newest issue on iPhone is random `error-report.com` website showing up and not being able to see what is going on. Or maybe sites just not working because the domain is blocked or something? Not sure. Added additional filters to allow `error-report.com` and `html-load.com` to improve site accessibility.

`html-load.com` was for SourceForge not working when trying to download TempleOS. Some sites also appear to hard-fail if `html-load.com` or rotating `*.stg.html-load.com` hosts are blocked, so DNS-level filtering is too coarse for those ad links. Browser-side cosmetic/URL rules are the better place to clean those up.