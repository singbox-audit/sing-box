#!/usr/bin/env bash
set -euo pipefail

tag=$1
dir=$2
repo=${GITHUB_REPOSITORY:?}
sha=${GITHUB_SHA:?}
if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
  remote_tag=$(git ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}" | tail -1 | cut -f1)
  if [[ "$remote_tag" != "$sha" ]]; then
    echo "Release tag $tag does not point at build commit $sha" >&2
    exit 1
  fi
else
  # A manual build can prepare a draft for a new version.
  if git ls-remote --exit-code origin "refs/tags/$tag" >/dev/null; then
    git fetch --no-tags origin "refs/tags/$tag"
    test "$(git rev-parse 'FETCH_HEAD^{commit}')" = "$sha"
  fi
  gh release create "$tag" --repo "$repo" --target "$sha" --draft --title "$tag" --notes ""
fi
gh release upload "$tag" "$dir"/* --repo "$repo" --clobber
