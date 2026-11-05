#!/bin/sh
# The package's conformance run (docs/extending/listeners.md, the
# four-piece contract's fourth piece): drives the platform repository's
# official-package e2e legs against this checkout -- the classic DNS leg
# over the UDP face (enroll, contact, task round trip under the zone) and
# the wire-level DoH-face leg. A release passes before it names itself a
# carrier.
#
# Environment:
#   ROD_CHECKOUT   a Rod platform checkout (default: ../Rod beside this repo)
#   ROD_IMPLANT_RUST_DIR   the Rust reference implant tree
#                  (same resolution the platform's own tests use)
#   ROD_LISTENER_DOH_DIR   this checkout (the export is done for you)
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
package_root=$(dirname "$here")
rod_checkout=${ROD_CHECKOUT:-$(dirname "$package_root")/Rod}

if [ ! -d "$rod_checkout/src/teamserver" ]; then
    echo "conformance: no Rod checkout at $rod_checkout -- set ROD_CHECKOUT" >&2
    exit 1
fi

echo "building the server tree"
"$package_root/build.sh"

echo "running the official doh-package legs"
cd "$rod_checkout"
export ROD_LISTENER_DOH_DIR="$package_root"
dotnet test tests/teamserver/Rod.Integration.Tests/Rod.Integration.Tests.csproj \
    --filter "FullyQualifiedName~OfficialListenerPackageEndToEndTests.DohPackage"
