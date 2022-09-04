#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )/.."

env GOOS="${GOOS:-linux}" GOARCH="${GOARCH:-arm}" GOARM="${GOARM:-7}" go build -ldflags="-s -w" -o rtsptoweb-minimal

echo "spawning subshell - please deploy '*.nix' and '*.bin' to your server."
echo "once done, press ctrl-D and the binary file will be deleted automatically."

$SHELL -i

rm rtsptoweb-minimal

echo "cleanup complete."
