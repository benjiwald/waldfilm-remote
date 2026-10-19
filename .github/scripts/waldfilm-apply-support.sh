#!/usr/bin/env bash
# Switch the checked-out tree from "Waldfilm Remote" to the "Waldfilm Support" variant
# (customer build, incoming connections only). The Rust side is switched via the
# compile-time env WALDFILM_SUPPORT, which this script exports to $GITHUB_ENV.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ -n "${GITHUB_ENV:-}" ]]; then echo "WALDFILM_SUPPORT=1" >> "$GITHUB_ENV"; fi
cp -Rv res/waldfilm-support/overlay/. .
# portable sed -i (GNU and BSD)
sedi() { if sed --version >/dev/null 2>&1; then sed -i "$@"; else sed -i '' "$@"; fi; }
for f in flutter/windows/runner/Runner.rc Cargo.toml libs/portable/Cargo.toml \
         flutter/macos/Runner/Configs/AppInfo.xcconfig flutter/macos/Runner.xcodeproj/project.pbxproj \
         flutter/macos/Runner/Info.plist; do
  sedi -e 's/Waldfilm Remote/Waldfilm Support/g' \
       -e 's/"waldfilm-remote"/"waldfilm-support"/g' \
       -e 's/WaldfilmRemote/WaldfilmSupport/g' \
       -e 's/waldfilmremote/waldfilmsupport/g' \
       -e 's/at\.waldfilm\.remote/at.waldfilm.support/g' "$f"
done
grep -n "Waldfilm\|waldfilm" flutter/windows/runner/Runner.rc Cargo.toml libs/portable/Cargo.toml \
  flutter/macos/Runner/Configs/AppInfo.xcconfig flutter/macos/Runner/Info.plist || true
grep -n "PRODUCT_BUNDLE_IDENTIFIER" flutter/macos/Runner.xcodeproj/project.pbxproj
