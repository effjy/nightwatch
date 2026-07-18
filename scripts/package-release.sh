#!/bin/sh
set -eu
umask 022

version=${1:-0.1.0}
case "$version" in
    *[!A-Za-z0-9._-]*|'')
        echo "Invalid release version: $version" >&2
        exit 2
        ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(dirname -- "$script_dir")
archive_name="nightwatch-$version"
output_dir="$project_dir/dist"
archive="$output_dir/$archive_name.tar.gz"
source_date_epoch=${SOURCE_DATE_EPOCH:-1784289600}
case "$source_date_epoch" in
    *[!0-9]*|'')
        echo "Invalid SOURCE_DATE_EPOCH: $source_date_epoch" >&2
        exit 2
        ;;
esac
staging=$(mktemp -d "${TMPDIR:-/tmp}/nightwatch-release.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT HUP INT TERM

mkdir -p "$staging/$archive_name" "$output_dir"

copy_file() {
    source=$1
    destination=$2
    install -D -m 0644 "$project_dir/$source" \
        "$staging/$archive_name/$destination"
}

copy_executable() {
    source=$1
    destination=$2
    install -D -m 0755 "$project_dir/$source" \
        "$staging/$archive_name/$destination"
}

for file in README.md GITHUB.md PROJECT.md THREAT-MODEL.md DESIGN.md \
        DEMO.md RELEASE-CHECKLIST.md LICENSE Makefile .gitignore; do
    copy_file "$file" "$file"
done

for file in "$project_dir"/include/*.hpp "$project_dir"/src/*.cpp \
        "$project_dir"/tests/*.cpp; do
    relative=${file#"$project_dir/"}
    copy_file "$relative" "$relative"
done

copy_file tests/golden/assurance-reports.sha256 \
    tests/golden/assurance-reports.sha256
copy_file titles/nightwatch-title.svg titles/nightwatch-title.svg
copy_file packaging/reviewed-executables.db packaging/reviewed-executables.db
copy_executable scripts/package-release.sh scripts/package-release.sh

tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
    -czf "$archive" -C "$staging" "$archive_name"
(cd "$output_dir" && sha256sum "$archive_name.tar.gz" \
    >"$archive_name.tar.gz.sha256")
chmod 0644 "$archive" "$archive.sha256"

echo "Release archive: $archive"
echo "Checksum:       $archive.sha256"
