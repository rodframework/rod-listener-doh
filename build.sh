#!/bin/sh
# Builds and self-tests the package's server assembly into bin/ -- one
# framework-dependent tree, one payload for every (os, arch) cell: the
# kernel host always carries the .NET runtime, so nothing larger is earned
# yet (Native-AOT single files ride the edge-host work). Run before
# `rod mod publish` -- nothing under bin/ is committed.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

dotnet publish src/Rod.Listener.Doh.csproj \
    -c Release \
    -o bin \
    -p:PublishDir="$here/bin/"

# The codec's wire form against the kernel's own bytes: a publish never
# rides an unverified codec.
dotnet bin/server.dll --selftest
