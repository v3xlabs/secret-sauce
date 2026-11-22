#!/usr/bin/env bash
# Rebuilds docs/demo.gif and docs/lettermark.svg of this checkout. Needs only Nix; run it from anywhere:
#   docs/demo/build.sh
# It records a real `sauce` session with VHS, draws the panels with headless chromium, composes the
# banner with ffmpeg and shrinks it with gifsicle. Tools and fonts come from the nixpkgs that
# flake.lock pins. Everything is made in a temporary folder that is removed at the end.
set -euo pipefail

here=$(cd "${BASH_SOURCE[0]%/*}" && pwd)
repo=$(cd "$here/../.." && pwd)

if [ -z "${DEMO_IN_NIX_SHELL:-}" ]; then
  export DEMO_IN_NIX_SHELL=1
  exec nix shell --inputs-from "$repo" \
    nixpkgs#bash nixpkgs#coreutils nixpkgs#git nixpkgs#gnutar \
    nixpkgs#vhs nixpkgs#ttyd nixpkgs#ffmpeg-headless nixpkgs#chromium nixpkgs#gifsicle nixpkgs#python3 \
    --command bash "$here/build.sh"
fi

export PYTHONDONTWRITEBYTECODE=1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# The example flake takes sauce from path:.. and needs a git repo, so the recording runs in a copy.
mkdir "$tmp/repo" "$tmp/work"
git -C "$repo" ls-files -z --cached --others --exclude-standard |
  tar -C "$repo" --null --ignore-failed-read -T - -cf - | tar -C "$tmp/repo" -xf -
git -C "$tmp/repo" init -q
git -C "$tmp/repo" add -A
GIT_AUTHOR_NAME=demo GIT_AUTHOR_EMAIL=demo@example.invalid \
  GIT_COMMITTER_NAME=demo GIT_COMMITTER_EMAIL=demo@example.invalid \
  git -C "$tmp/repo" commit -qm demo

# VHS (through ttyd and chromium) and the art chromium read the same fonts.
fonts=$(nix build --inputs-from "$repo" --no-link --print-out-paths nixpkgs#monocraft nixpkgs#minecraftia)
{
  echo '<?xml version="1.0"?>'
  echo '<!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">'
  echo '<fontconfig>'
  for font in $fonts; do echo "  <dir>$font/share/fonts</dir>"; done
  echo "  <cachedir>$tmp/fc-cache</cachedir>"
  echo '</fontconfig>'
} > "$tmp/fonts.conf"
export FONTCONFIG_FILE="$tmp/fonts.conf"

nix build "$tmp/repo#default" --out-link "$tmp/sauce"
export PATH="$tmp/sauce/bin:$PATH"
export NIX_CONFIG="${NIX_CONFIG:+$NIX_CONFIG$'\n'}warn-dirty = false"

cd "$tmp/work"
vhs "$here/sauce.tape"
python3 "$here/art.py" "$tmp/repo/example"
python3 "$here/build.py" raw.mp4 "$tmp/demo.gif"
python3 "$here/lettermark.py" "$tmp/lettermark.svg"

cp "$tmp/demo.gif" "$repo/docs/demo.gif"
cp "$tmp/lettermark.svg" "$repo/docs/lettermark.svg"
