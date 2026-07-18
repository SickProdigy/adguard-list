# SickProdigy Adguard Filter Lists

My personal AdGuard blocker/unblocker lists.

## Lists

- `assets/Filter-1.txt`: Compiled list built from `Filter-2.txt`, `Filter-3.txt`, and `Filter-4.txt`.
- `assets/Filter-2.txt`: Manual DNS allow/block rules. This is the hand-maintained network-wide list.
- `assets/Filter-3.txt`: Karakeep generated allowlist candidates. This is written by the separate `adguard-karakeep` export script.
- `assets/Filter-4.txt`: Browser add-on rules. Use this in AdGuard Browser Extension, uBlock Origin, or another browser/content blocker that supports URL parameter removal, cosmetic filtering, and URL/path rules.

## Installation

### AdGuard Home / DNS filters

Add the compiled list as a custom DNS blocklist:

https://gitea.sickgaming.net/sickprodigy/adguard-list/raw/branch/main/assets/Filter-1.txt

`Filter-1.txt` is generated from the component files. The main hand-maintained DNS source is `Filter-2.txt`; Karakeep allowlist candidates are exported into `Filter-3.txt`; browser-only cleanup lives in `Filter-4.txt`.

The DNS rules are mainly to block missing trackers and bad actors that are still able to load on my network. Use them alongside other DNS filters. They also unblock a few domains to keep sites usable, like `t.co`, `error-report.com`, and `html-load.com`.

### Karakeep allowlist export

The separate `adguard-karakeep` script should export its generated allowlist to:

`assets/Filter-3.txt`

After regenerating `Filter-3.txt`, rebuild `Filter-1.txt` from `Filter-2.txt`, `Filter-3.txt`, and `Filter-4.txt` before publishing the compiled list.

The reference exporter is included at `scripts/export-karakeep-allowlist.py`. With Karakeep and optional AdGuard details in `.env`, run:

```powershell
python scripts\export-karakeep-allowlist.py --check-adguard --allowlist-path assets\Filter-3.txt
```


### Rebuilding the compiled list

Use any of these equivalent helper scripts to rebuild `assets/Filter-1.txt` from `Filter-2.txt`, `Filter-3.txt`, and `Filter-4.txt`:

```bash
bash scripts/compile-filters.sh
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\compile-filters.ps1
```

```powershell
python scripts\compile-filters.py
```

### Browser add-on filters

Add this as a custom browser/content filter:

https://gitea.sickgaming.net/sickprodigy/adguard-list/raw/branch/main/assets/Filter-4.txt

This list contains rules that AdGuard Home cannot apply, including `$removeparam`, cosmetic selectors like `##`, and URL/path/script rules. These need a browser extension or local client that can see full HTTPS URLs and page elements.

## Notes

A lot of time for paywall sites you can just disable JavaScript and many functions will disappear. Other times you will need userscripts; magnolia1234 has explained it well in their scripts if interested.

Newest issue on iPhone is random `error-report.com` website showing up and not being able to see what is going on. Or maybe sites just not working because the domain is blocked or something? Not sure. Added additional filters to allow `error-report.com` and `html-load.com` to improve site accessibility.

`html-load.com` was for SourceForge not working when trying to download TempleOS. Some sites also appear to hard-fail if `html-load.com` or rotating `*.stg.html-load.com` hosts are blocked, so DNS-level filtering is too coarse for those ad links. Browser-side cosmetic/URL rules are the better place to clean those up.


