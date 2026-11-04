#!/usr/bin/env bash
# Regenerate nix/patches from a herdr branch rebased onto the pinned tag.
#
#   nix/update-herdr-patches.sh ~/git/herdr [branch]
#
# Keep the series in a herdr branch on top of the tag pinned in flake.nix;
# to move to a new release: rebase the branch, bump herdr.url, rerun this.
set -euo pipefail

herdr=${1:?usage: $0 <herdr-checkout> [branch]}
branch=${2:-herdr-eternal}
root=$(cd "$(dirname "$0")/.." && pwd)
base=$(sed -n 's|.*herdr.url = "github:ogulcancelik/herdr/\(.*\)";|\1|p' "$root/flake.nix")

git -C "$herdr" merge-base --is-ancestor "$base" "$branch" || {
  echo "$branch is not based on $base; rebase it first" >&2
  exit 1
}
rm -f "$root"/nix/patches/*.patch
git -C "$herdr" format-patch --quiet --zero-commit --no-signature \
  -o "$root/nix/patches" "$base..$branch"
ls "$root/nix/patches"
