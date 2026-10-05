#!/usr/bin/env bash
# Build from any working directory; local builds and CI use this same entrypoint.
set -euo pipefail

recipe_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$recipe_dir/../.." && pwd)

check_recipe() {
    local script command arguments source
    for script in build.sh customize.sh smoke-test.sh; do
        bash -n "$recipe_dir/$script"
    done
    for script in .xsession startwm.sh; do
        sh -n "$recipe_dir/$script"
    done
    while read -r command arguments; do
        if [[ "$command" == upload ]]; then
            source=${arguments%%:*}
            # Generated below and mounted at /build in the builder container.
            if [[ "$source" == /build/sauronagent.deb ]]; then
                continue
            fi
            if [[ ! -f "$recipe_dir/$source" ]]; then
                echo "Missing recipe upload: $source" >&2
                return 1
            fi
        fi
    done < "$recipe_dir/run-command.virt"
}

check_recipe
if [[ "${1:-}" == --check ]]; then
    echo "Image recipe syntax and static upload sources verified."
    exit 0
fi
version=${1:-0.0.0}
if [[ $# -gt 1 || ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Usage: $0 [MAJOR.MINOR.PATCH | --check]" >&2
    exit 2
fi
for tool in curl sha256sum docker flock make go python3 git; do
    command -v "$tool" >/dev/null || { echo "Required command missing: $tool" >&2; exit 1; }
done
if [[ $(uname -m) != x86_64 ]]; then
    echo "This image build requires a Linux x86_64 host." >&2
    exit 1
fi

cache_dir="$repo_dir/.cache/images/ubuntu24.04-gnome"
output_dir="$repo_dir/dist/images/ubuntu24.04-gnome"
mkdir -p "$cache_dir" "$output_dir"
# The agent package and final filenames are shared by builds of this recipe.
exec 9>"$cache_dir/build.lock"
flock -n 9 || { echo "Another ubuntu24.04-gnome image build is running." >&2; exit 1; }
work_dir=$(mktemp -d "$cache_dir/build.XXXXXXXX")
cleanup() {
    local status=$?
    trap - EXIT
    # Stop only this build's container before removing its mounted workspace.
    if [[ -s "$work_dir/container.cid" ]]; then
        docker rm --force "$(cat "$work_dir/container.cid")" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$work_dir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

source_name=noble-server-cloudimg-amd64.img
source_url="https://cloud-images.ubuntu.com/noble/current/$source_name"
curl --fail --location --retry 3 --output "$work_dir/SHA256SUMS" \
    https://cloud-images.ubuntu.com/noble/current/SHA256SUMS
source_sha=$(awk -v name="$source_name" '$2 == name || $2 == "*" name { print $1 }' "$work_dir/SHA256SUMS")
if [[ ! "$source_sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "No unique SHA-256 for $source_name in Ubuntu's checksum list." >&2
    exit 1
fi
source_image="$cache_dir/$source_sha.img"
if [[ ! -f "$source_image" ]]; then
    curl --fail --location --retry 3 --output "$work_dir/source.img" "$source_url"
    printf '%s  %s\n' "$source_sha" "$work_dir/source.img" | sha256sum --check
    mv -- "$work_dir/source.img" "$source_image"
else
    printf '%s  %s\n' "$source_sha" "$source_image" | sha256sum --check
fi

make -C "$repo_dir" sauron-deb VERSION="$version" DEB_ARCH=amd64
cp -- "$repo_dir/dist/sauronagent_${version}_amd64.deb" "$work_dir/sauronagent.deb"

tools_image=ghcr.io/define42/virt-tools-container:latest
docker pull "$tools_image"
tools_id=$(docker image inspect "$tools_image" --format '{{.Id}}')
tools_digest=$(docker image inspect "$tools_image" --format '{{index .RepoDigests 0}}')
docker_args=(--rm --cidfile "$work_dir/container.cid" --platform linux/amd64
    --volume "$recipe_dir:/recipe:ro"
    --volume "$source_image:/source.img:ro"
    --volume "$work_dir:/build"
    --workdir /recipe)
if [[ -e /dev/kvm ]]; then
    docker_args+=(--device /dev/kvm)
fi
docker run "${docker_args[@]}" "$tools_id" \
    bash /recipe/customize.sh "$(id -u):$(id -g)"

image_name="ubuntu24.04-gnome-v$version.img"
mv -- "$work_dir/desktop.img" "$work_dir/$image_name"
(
    cd -- "$work_dir"
    sha256sum "$image_name" > "$image_name.sha256"
)
git_commit=$(git -C "$repo_dir" rev-parse HEAD)
git_dirty=false
if [[ -n $(git -C "$repo_dir" status --porcelain) ]]; then
    git_dirty=true
fi
python3 - "$work_dir/$image_name.manifest.json" "$version" "$git_commit" "$git_dirty" \
    "$source_url" "$source_sha" "$tools_digest" <<'PY'
import datetime
import json
import sys

destination, version, commit, dirty, source, checksum, tools = sys.argv[1:]
with open(destination, "w", encoding="utf-8") as manifest:
    json.dump({
        "image": "ubuntu24.04-gnome",
        "version": version,
        "architecture": "amd64",
        "format": "qcow2",
        "git_commit": commit,
        "git_dirty": dirty == "true",
        "sauronagent_version": version,
        "source_url": source,
        "source_sha256": checksum,
        "builder_image": tools,
        "built_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }, manifest, indent=2)
    manifest.write("\n")
PY
mv -- "$work_dir/$image_name" "$work_dir/$image_name.sha256" \
    "$work_dir/$image_name.manifest.json" "$output_dir/"
echo "Built $output_dir/$image_name"
