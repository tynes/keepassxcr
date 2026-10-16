#!/usr/bin/env bash
# Build upstream keepassxc-cli with a software YubiKey, for test_yubikey_compat.py.
#
# Only the device call (YubiKey::challenge) is replaced, by an HMAC-SHA1 of the
# challenge padded exactly as KeePassXC's USB and PC/SC drivers pad it
# (keepassxc-software-yubikey.patch). Key derivation and the KDBX code are
# upstream's. Prints the path of the built keepassxc-cli.
#
# Needs cmake, a C++ compiler and KeePassXC's build dependencies with YubiKey
# support. On Debian/Ubuntu:
#   apt install cmake g++ qtbase5-dev qtbase5-private-dev qttools5-dev qttools5-dev-tools \
#     libqt5svg5-dev libbotan-2-dev libargon2-dev zlib1g-dev libminizip-dev libqrencode-dev \
#     libreadline-dev libykpers-1-dev libyubikey-dev libpcsclite-dev libusb-1.0-0-dev
set -euo pipefail

VERSION=${KEEPASSXC_VERSION:-2.7.12}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$ROOT/target/keepassxc-software-yubikey/$VERSION
CLI=$WORK/build/src/cli/keepassxc-cli

if [[ -x $CLI ]]; then
  echo "$CLI"
  exit 0
fi

if [[ ! -d $WORK/src ]]; then
  mkdir -p "$WORK"
  git clone --quiet --depth 1 --branch "$VERSION" https://github.com/keepassxreboot/keepassxc.git "$WORK/src" >&2
  git -C "$WORK/src" apply "$ROOT/tests/keepassxc-software-yubikey.patch"
fi

mkdir -p "$WORK/build"
cmake -S "$WORK/src" -B "$WORK/build" -DCMAKE_BUILD_TYPE=Release \
  -DWITH_XC_YUBIKEY=ON -DWITH_XC_X11=OFF -DWITH_XC_AUTOTYPE=OFF -DWITH_XC_BROWSER=OFF \
  -DWITH_XC_KEESHARE=OFF -DWITH_XC_NETWORKING=OFF -DWITH_XC_SSHAGENT=OFF \
  -DWITH_XC_FDOSECRETS=OFF -DWITH_XC_UPDATECHECK=OFF -DWITH_XC_DOCS=OFF \
  -DWITH_GUI_TESTS=OFF -DWITH_TESTS=OFF >&2
cmake --build "$WORK/build" --target keepassxc-cli -j "$(getconf _NPROCESSORS_ONLN)" >&2
echo "$CLI"
