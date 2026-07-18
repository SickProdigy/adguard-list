#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
assets="$root/assets"
output="$assets/Filter-1.txt"

sources=(
  "Filter-2.txt|Manual DNS allow/block rules"
  "Filter-3.txt|Karakeep generated allowlist candidates"
  "Filter-4.txt|Browser add-on rules"
)

{
  printf '%s\n' '! Title: Sick Prodigy Compiled AdGuard List'
  printf '%s\n' '! Expires: 1 day (update frequency)'
  printf '%s\n' '! Description: Compiled from Filter-2.txt, Filter-3.txt, and Filter-4.txt.'
  printf '%s\n' '! Homepage: https://gitea.sickgaming.net/sickprodigy/adguard-list'
  printf '%s\n' '! License: https://gitea.sickgaming.net/sickprodigy/adguard-list/raw/branch/main/LICENSE'
  printf '! Last modified: %s\n' "$(date +'%m/%d/%Y')"
  printf '%s\n' '! Version: generated'
  printf '%s\n' '!'
  printf '%s\n' '! Source files:'

  for source in "${sources[@]}"; do
    name="${source%%|*}"
    description="${source#*|}"
    printf '! - %s: %s\n' "$name" "$description"
  done

  for source in "${sources[@]}"; do
    name="${source%%|*}"
    description="${source#*|}"
    path="$assets/$name"
    if [[ ! -f "$path" ]]; then
      printf 'Missing source filter: %s\n' "$path" >&2
      exit 1
    fi

    printf '\n%s\n' '! ============================================================================='
    printf '! Begin %s: %s\n' "$name" "$description"
    printf '%s\n' '! ============================================================================='
    cat "$path"
    printf '\n! End %s\n' "$name"
  done
} > "$output"

printf 'Wrote assets/Filter-1.txt\n'

