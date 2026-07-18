#!/usr/bin/env python3
"""Export Karakeep bookmarks and build reviewed AdGuard allowlist candidates.

Examples:
  python scripts/export-karakeep-allowlist.py
  python scripts/export-karakeep-allowlist.py --check-adguard
  python scripts/export-karakeep-allowlist.py --check-dns --only-resolvable
  python scripts/export-karakeep-allowlist.py --allow-subdomains

The script auto-loads a local .env file when present:
  KARAKEEP_SERVER_ADDR=http://karakeep.example:3000
  KARAKEEP_API_KEY=your_api_key
  KARAKEEP_OUTPUT_DIR=exports
  KARAKEEP_ALLOWLIST_PATH=assets/Filter-3.txt

Optional AdGuard Home audit env vars:
  ADGUARD_URL=http://adguard.example:3000
  ADGUARD_USER=your_user
  ADGUARD_PASSWORD=your_password
  ADGUARD_PERSONAL_FILTER_NAME=My Personal List
  ADGUARD_PERSONAL_FILTER_ID=1234567890

Outputs:
  bookmarks.raw.json
  bookmarks.links.csv
  domains.csv
  hosts.csv
  karakeep-allowlist-candidates.txt, unless KARAKEEP_ALLOWLIST_PATH/--allowlist-path is set
  karakeep-allowlist-blocked-review.txt
  adguard-conflicts.csv
  invalid-hosts.csv
  summary.json
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import socket
import sys
from collections import Counter
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen

DEFAULT_EXCLUDED_DOMAINS = {
    "facebook.com",
    "google.com",
    "instagram.com",
    "reddit.com",
    "t.co",
    "twitter.com",
    "x.com",
    "youtube.com",
}

SECOND_LEVEL_SUFFIXES = {
    "ac.uk", "co.jp", "co.kr", "co.nz", "co.uk", "com.au", "com.br",
    "com.mx", "com.tr", "com.tw", "edu.au", "gov.uk", "net.au",
    "org.au", "org.uk",
}

TRACKING_PARAMS = {
    "fbclid", "gclid", "igshid", "mc_cid", "mc_eid", "msclkid", "ref",
    "spm", "utm_campaign", "utm_content", "utm_id", "utm_medium", "utm_name",
    "utm_source", "utm_term",
}

HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def load_dotenv(path: Path = Path(".env")) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip().strip('"').strip("'")
        if name and name not in os.environ:
            os.environ[name] = value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export Karakeep link bookmarks and generate reviewed AdGuard allowlist candidates."
    )
    parser.add_argument("--server-addr", default=os.getenv("KARAKEEP_SERVER_ADDR"), help="Karakeep base URL.")
    parser.add_argument("--api-key", default=os.getenv("KARAKEEP_API_KEY"), help="Karakeep API key.")
    parser.add_argument(
        "--output-dir",
        default=os.getenv("KARAKEEP_OUTPUT_DIR", "exports"),
        help="Local export folder. Default: KARAKEEP_OUTPUT_DIR or exports."
    )
    parser.add_argument(
        "--allowlist-path",
        default=os.getenv("KARAKEEP_ALLOWLIST_PATH"),
        help="Optional path for the generated allowlist filter. Default: output-dir/karakeep-allowlist-candidates.txt.",
    )
    parser.add_argument("--limit", type=int, default=100, help="Bookmarks per API page. Default: 100")
    parser.add_argument("--include-archived", action="store_true", help="Include archived bookmarks.")
    parser.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="Do not exclude common large/social domains from allowlist candidates.",
    )
    parser.add_argument(
        "--exclude-domain",
        action="append",
        default=[],
        help="Extra registrable domain to exclude from allowlist candidates. Repeatable.",
    )
    parser.add_argument(
        "--allow-subdomains",
        action="store_true",
        help="Generate allow rules for exact hosts instead of registrable/root domains.",
    )
    parser.add_argument(
        "--include-ip-hosts",
        action="store_true",
        help="Include IP-address hosts in the generated allowlist candidate file.",
    )
    parser.add_argument(
        "--check-dns",
        action="store_true",
        help="Resolve candidate domains/hosts and record whether they still exist.",
    )
    parser.add_argument(
        "--only-resolvable",
        action="store_true",
        help="When used with --check-dns, only include resolvable names in allowlist candidates.",
    )
    parser.add_argument(
        "--dns-timeout",
        type=float,
        default=1.5,
        help="DNS lookup timeout in seconds for --check-dns. Default: 1.5",
    )
    parser.add_argument(
        "--check-adguard",
        action="store_true",
        help="Audit candidates against live AdGuard Home using ADGUARD_URL/ADGUARD_USER/ADGUARD_PASSWORD.",
    )
    parser.add_argument("--adguard-url", default=os.getenv("ADGUARD_URL"), help="AdGuard Home URL for --check-adguard.")
    parser.add_argument("--adguard-user", default=os.getenv("ADGUARD_USER"), help="AdGuard Home username.")
    parser.add_argument("--adguard-password", default=os.getenv("ADGUARD_PASSWORD"), help="AdGuard Home password.")
    parser.add_argument(
        "--include-blocked-conflicts",
        action="store_true",
        help="Include domains currently blocked by AdGuard in the main allowlist candidate file. Default is review-only.",
    )
    return parser.parse_args()


def normalize_server_addr(server_addr: str | None) -> str:
    if not server_addr:
        raise ValueError("missing Karakeep server address")
    server_addr = server_addr.strip().rstrip("/")
    if not server_addr.startswith(("http://", "https://")):
        raise ValueError("server address must start with http:// or https://")
    return server_addr


def fetch_json(url: str, api_key: str) -> dict[str, Any]:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "adguard-karakeep-export/1.0",
        },
    )
    try:
        with urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Karakeep API failed: HTTP {exc.code}: {body}") from exc
    except URLError as exc:
        raise RuntimeError(f"Karakeep API failed: {exc.reason}") from exc


def iter_bookmark_pages(server_addr: str, api_key: str, limit: int, include_archived: bool):
    cursor: str | None = None
    while True:
        params = {"limit": str(limit), "includeContent": "false", "sortOrder": "desc"}
        if not include_archived:
            params["archived"] = "false"
        if cursor:
            params["cursor"] = cursor
        payload = fetch_json(f"{server_addr}/api/v1/bookmarks?{urlencode(params)}", api_key)
        yield payload
        cursor = payload.get("nextCursor") or payload.get("next_cursor")
        if not cursor:
            break


def extract_bookmarks(payload: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("bookmarks", "items", "data"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def bookmark_url(bookmark: dict[str, Any]) -> str | None:
    content = bookmark.get("content")
    if isinstance(content, dict):
        content_type = content.get("type")
        url = content.get("url")
        if content_type in (None, "link") and isinstance(url, str) and url:
            return url
    for key in ("url", "link", "href"):
        url = bookmark.get(key)
        if isinstance(url, str) and url:
            return url
    return None


def clean_url(raw_url: str) -> str:
    parsed = urlparse(raw_url.strip())
    if not parsed.scheme or not parsed.netloc:
        return raw_url.strip()
    query = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key.lower() not in TRACKING_PARAMS
    ]
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, "", urlencode(query, doseq=True), ""))


def host_from_url(raw_url: str) -> str | None:
    host = urlparse(raw_url).hostname
    if not host:
        return None
    host = host.lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def is_ip_host(host: str) -> bool:
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


def is_valid_hostname(host: str) -> bool:
    if is_ip_host(host):
        return True
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    if len(ascii_host) > 253 or "." not in ascii_host:
        return False
    labels = ascii_host.split(".")
    return all(HOST_LABEL_RE.match(label) for label in labels)


def registrable_domain(host: str) -> str:
    if is_ip_host(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    suffix2 = ".".join(parts[-2:])
    if suffix2 in SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix2


def dns_resolves(name: str, timeout: float) -> bool:
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        socket.getaddrinfo(name, None)
        return True
    except OSError:
        return False
    finally:
        socket.setdefaulttimeout(old_timeout)


def adguard_request_json(opener, base_url: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(f"{base_url}{path}", data=data, headers=headers)
    with opener.open(request, timeout=30) as response:
        raw = response.read().decode("utf-8")
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}


def adguard_login(base_url: str, username: str, password: str):
    opener = build_opener(HTTPCookieProcessor())
    adguard_request_json(opener, base_url, "/control/login", {"name": username, "password": password})
    return opener


def adguard_check_host(opener, base_url: str, name: str) -> dict[str, Any]:
    return adguard_request_json(opener, base_url, f"/control/filtering/check_host?{urlencode({'name': name})}")


def adguard_filter_names(opener, base_url: str) -> dict[str, str]:
    payload = adguard_request_json(opener, base_url, "/control/filtering/status")
    names = {"0": "Custom filtering rules"}
    for item in payload.get("filters", []):
        names[str(item.get("id", ""))] = item.get("name", "")
    return names


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def allow_rule(name: str) -> str:
    return f"@@||{name}^"


def write_allowlist(path: Path, title: str, description: str, generated_at: str, scope: str, names: list[str]) -> None:
    lines = [
        f"! Title: {title}",
        f"! Description: {description}",
        f"! Last generated: {generated_at}",
        f"! Scope: {scope}",
        "!",
    ]
    lines.extend(allow_rule(name) for name in names)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def export_files(
    output_dir: Path,
    bookmarks: list[dict[str, Any]],
    excluded_domains: set[str],
    allow_subdomains: bool,
    include_ip_hosts: bool,
    check_dns: bool,
    only_resolvable: bool,
    dns_timeout: float,
    check_adguard: bool,
    adguard_url: str | None,
    adguard_user: str | None,
    adguard_password: str | None,
    include_blocked_conflicts: bool,
    allowlist_output_path: Path | None = None,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    link_rows: list[dict[str, Any]] = []
    invalid_rows: list[dict[str, Any]] = []
    links_by_domain: dict[str, list[dict[str, Any]]] = {}
    links_by_host: dict[str, list[dict[str, Any]]] = {}
    host_counts: Counter[str] = Counter()
    domain_counts: Counter[str] = Counter()

    for bookmark in bookmarks:
        url = bookmark_url(bookmark)
        if not url:
            continue
        cleaned = clean_url(url)
        host = host_from_url(cleaned)
        if not host:
            invalid_rows.append({"url": cleaned, "host": "", "reason": "missing_host"})
            continue
        valid_host = is_valid_hostname(host)
        domain = registrable_domain(host)
        if not valid_host:
            invalid_rows.append({"url": cleaned, "host": host, "reason": "invalid_hostname"})
            continue
        host_counts[host] += 1
        domain_counts[domain] += 1
        row = {
            "id": bookmark.get("id", ""),
            "title": bookmark.get("title") or bookmark.get("name") or "",
            "url": cleaned,
            "host": host,
            "domain": domain,
            "createdAt": bookmark.get("createdAt") or bookmark.get("created_at") or "",
            "archived": bookmark.get("archived", ""),
        }
        link_rows.append(row)
        links_by_host.setdefault(host, []).append(row)
        links_by_domain.setdefault(domain, []).append(row)

    candidate_counts = host_counts if allow_subdomains else domain_counts
    links_by_candidate = links_by_host if allow_subdomains else links_by_domain
    all_candidates = sorted(candidate_counts)

    dns_status: dict[str, str] = {}
    if check_dns:
        for index, name in enumerate(all_candidates, 1):
            dns_status[name] = "resolves" if dns_resolves(name, dns_timeout) else "not_found"
            if index % 250 == 0:
                print(f"dns checked {index}/{len(all_candidates)}")

    adguard_status: dict[str, dict[str, Any]] = {}
    if check_adguard:
        if not (adguard_url and adguard_user and adguard_password):
            raise RuntimeError("--check-adguard requires ADGUARD_URL, ADGUARD_USER, and ADGUARD_PASSWORD")
        base_url = adguard_url.rstrip("/")
        opener = adguard_login(base_url, adguard_user, adguard_password)
        filter_names = adguard_filter_names(opener, base_url)
        for index, name in enumerate(all_candidates, 1):
            payload = adguard_check_host(opener, base_url, name)
            reason = payload.get("reason", "")
            rule = payload.get("rule", "")
            if reason != "NotFilteredNotFound" or rule:
                payload["filter_name"] = filter_names.get(str(payload.get("filter_id", "")), "")
                adguard_status[name] = payload
            if index % 250 == 0:
                print(f"adguard checked {index}/{len(all_candidates)}")

    domain_rows = []
    for domain, count in sorted(domain_counts.items()):
        domain_rows.append({
            "domain": domain,
            "count": count,
            "excluded": str(domain in excluded_domains).lower(),
            "valid": str(is_valid_hostname(domain)).lower(),
            "dns_status": dns_status.get(domain, "not_checked"),
            "adguard_reason": adguard_status.get(domain, {}).get("reason", ""),
            "adguard_rule": adguard_status.get(domain, {}).get("rule", ""),
            "adguard_filter_id": adguard_status.get(domain, {}).get("filter_id", ""),
            "adguard_filter_name": adguard_status.get(domain, {}).get("filter_name", ""),
        })

    host_rows = []
    for host, count in sorted(host_counts.items()):
        host_rows.append({
            "host": host,
            "domain": registrable_domain(host),
            "count": count,
            "is_ip": str(is_ip_host(host)).lower(),
            "valid": str(is_valid_hostname(host)).lower(),
            "dns_status": dns_status.get(host, "not_checked"),
            "adguard_reason": adguard_status.get(host, {}).get("reason", ""),
            "adguard_rule": adguard_status.get(host, {}).get("rule", ""),
            "adguard_filter_id": adguard_status.get(host, {}).get("filter_id", ""),
            "adguard_filter_name": adguard_status.get(host, {}).get("filter_name", ""),
        })

    personal_filter_name = os.getenv("ADGUARD_PERSONAL_FILTER_NAME", "")
    personal_filter_id = os.getenv("ADGUARD_PERSONAL_FILTER_ID", "")

    def filter_source(payload: dict[str, Any]) -> str:
        filter_id = str(payload.get("filter_id", ""))
        filter_name = str(payload.get("filter_name", ""))
        if filter_id == "0":
            return "custom"
        if (personal_filter_name and filter_name == personal_filter_name) or (personal_filter_id and filter_id == personal_filter_id):
            return "personal"
        return "upstream"

    adguard_matches = []
    for name, payload in sorted(adguard_status.items()):
        source_links = links_by_candidate.get(name, [])
        sample_links = source_links[:3]
        adguard_matches.append({
            "name": name,
            "reason": payload.get("reason", ""),
            "rule": payload.get("rule", ""),
            "filter_id": payload.get("filter_id", ""),
            "filter_name": payload.get("filter_name", ""),
            "filter_source": filter_source(payload),
            "count": candidate_counts.get(name, 0),
            "sample_titles": " | ".join(str(link.get("title", "")) for link in sample_links),
            "sample_urls": " | ".join(str(link.get("url", "")) for link in sample_links),
        })
    blocked_conflicts = [row for row in adguard_matches if row["reason"] == "FilteredBlackList"]
    whitelist_matches = [row for row in adguard_matches if "WhiteList" in row["reason"]]
    other_matches = [row for row in adguard_matches if row not in blocked_conflicts and row not in whitelist_matches]

    def is_candidate_allowed(name: str) -> bool:
        domain = registrable_domain(name)
        if domain in excluded_domains:
            return False
        if is_ip_host(name) and not include_ip_hosts:
            return False
        if check_dns and only_resolvable and dns_status.get(name) != "resolves":
            return False
        adguard_payload = adguard_status.get(name)
        if adguard_payload and adguard_payload.get("reason") == "FilteredBlackList" and not include_blocked_conflicts:
            return False
        return True

    allowlist_names = [name for name in all_candidates if is_candidate_allowed(name)]
    blocked_review_names = [
        name
        for name, payload in sorted(adguard_status.items())
        if payload.get("reason") == "FilteredBlackList" and registrable_domain(name) not in excluded_domains
    ]

    raw_path = output_dir / "bookmarks.raw.json"
    links_path = output_dir / "bookmarks.links.csv"
    domains_path = output_dir / "domains.csv"
    hosts_path = output_dir / "hosts.csv"
    invalid_path = output_dir / "invalid-hosts.csv"
    conflicts_path = output_dir / "adguard-conflicts.csv"
    whitelist_matches_path = output_dir / "adguard-whitelist-matches.csv"
    other_matches_path = output_dir / "adguard-other-matches.csv"
    allowlist_path = allowlist_output_path or output_dir / "karakeep-allowlist-candidates.txt"
    blocked_review_path = output_dir / "karakeep-allowlist-blocked-review.txt"
    allowlist_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "summary.json"

    raw_path.write_text(json.dumps(bookmarks, indent=2, ensure_ascii=False), encoding="utf-8")
    write_csv(links_path, link_rows, ["id", "title", "url", "host", "domain", "createdAt", "archived"])
    write_csv(domains_path, domain_rows, ["domain", "count", "excluded", "valid", "dns_status", "adguard_reason", "adguard_rule", "adguard_filter_id", "adguard_filter_name"])
    write_csv(hosts_path, host_rows, ["host", "domain", "count", "is_ip", "valid", "dns_status", "adguard_reason", "adguard_rule", "adguard_filter_id", "adguard_filter_name"])
    write_csv(invalid_path, invalid_rows, ["url", "host", "reason"])
    match_fields = ["name", "reason", "rule", "filter_id", "filter_name", "filter_source", "count", "sample_titles", "sample_urls"]
    write_csv(conflicts_path, blocked_conflicts, match_fields)
    write_csv(whitelist_matches_path, whitelist_matches, match_fields)
    write_csv(other_matches_path, other_matches, match_fields)

    scope = "exact hosts" if allow_subdomains else "registrable domains"
    write_allowlist(
        allowlist_path,
        "Karakeep Generated Allowlist Candidates",
        "Review before enabling. Blocked AdGuard conflicts are excluded unless --include-blocked-conflicts is used.",
        generated_at,
        scope,
        allowlist_names,
    )
    write_allowlist(
        blocked_review_path,
        "Karakeep Blocked-Domain Allowlist Review",
        "These saved domains are currently blocked by AdGuard. Manually review before allowing main domains.",
        generated_at,
        scope,
        blocked_review_names,
    )

    blocked_count = len(blocked_conflicts)
    whitelisted_count = len(whitelist_matches)
    summary = {
        "generatedAt": generated_at,
        "bookmarkCount": len(bookmarks),
        "linkCount": len(link_rows),
        "invalidHostCount": len(invalid_rows),
        "uniqueHosts": len(host_counts),
        "uniqueDomains": len(domain_counts),
        "allowlistCandidateCount": len(allowlist_names),
        "blockedReviewCandidateCount": len(blocked_review_names),
        "ipHostCount": sum(1 for host in host_counts if is_ip_host(host)),
        "dnsChecked": check_dns,
        "dnsResolvableCount": sum(1 for status in dns_status.values() if status == "resolves"),
        "adguardChecked": check_adguard,
        "adguardMatchCount": len(adguard_matches),
        "adguardBlockedConflictCount": blocked_count,
        "adguardWhitelistedConflictCount": whitelisted_count,
        "excludedDomains": sorted(domain for domain in domain_counts if domain in excluded_domains),
        "files": {
            "raw": str(raw_path),
            "links": str(links_path),
            "domains": str(domains_path),
            "hosts": str(hosts_path),
            "invalid_hosts": str(invalid_path),
            "conflicts": str(conflicts_path),
            "whitelist_matches": str(whitelist_matches_path),
            "other_matches": str(other_matches_path),
            "allowlist": str(allowlist_path),
            "blocked_review": str(blocked_review_path),
        },
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


def main() -> int:
    load_dotenv()
    args = parse_args()
    if not args.api_key:
        print("error: provide --api-key or set KARAKEEP_API_KEY", file=sys.stderr)
        return 2
    try:
        server_addr = normalize_server_addr(args.server_addr)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    excluded_domains = {domain.lower().strip() for domain in args.exclude_domain if domain.strip()}
    if not args.no_default_excludes:
        excluded_domains.update(DEFAULT_EXCLUDED_DOMAINS)

    bookmarks: list[dict[str, Any]] = []
    try:
        for page in iter_bookmark_pages(server_addr, args.api_key, args.limit, args.include_archived):
            bookmarks.extend(extract_bookmarks(page))
        export_files(
            Path(args.output_dir),
            bookmarks,
            excluded_domains,
            args.allow_subdomains,
            args.include_ip_hosts,
            args.check_dns,
            args.only_resolvable,
            args.dns_timeout,
            args.check_adguard,
            args.adguard_url,
            args.adguard_user,
            args.adguard_password,
            args.include_blocked_conflicts,
            Path(args.allowlist_path) if args.allowlist_path else None,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())





