#!/bin/sh

EVE="$(cd "$(dirname "$0")" && pwd)/../"
SOURCE="$(cd "$EVE/api" && pwd)"
EVE_OS_VERSION="$1"
OUT_FILE=$(basename "$2")
OUT_FULL_PATH="$(cd "$(dirname "$2")" && pwd)/$OUT_FILE"

if [ ! -d "$SOURCE" ] || [ $# -lt 2 ]; then
  echo "Usage: $0 <version> <output nupkg file>"
  exit 1
fi

case $(uname -m) in
x86_64) ;;
aarch64) ;;
*)
  echo "Unsupported architecture $(uname -m). Nothing to do" && exit 0
  ;;
esac

: >"$OUT_FULL_PATH"

cat <<__EOT__ | docker run --rm -v "$SOURCE:/api" -v "$OUT_FULL_PATH:/$OUT_FILE" -i mcr.microsoft.com/dotnet/sdk:6.0 sh
   TEMP_DIR="\$(mktemp -d)"
   cp -r /api/* "/\$TEMP_DIR"
   cd "/\$TEMP_DIR"
   # replace relative paths inside of README.md
   sed -i 's@(\.@(https://github.com/lf-edge/eve/blob/master/api@g' README.md
   dotnet build LFEdge.EVE.API.csproj -c Release /property:Version="$EVE_OS_VERSION" -o "/\$TEMP_DIR"
   cp "/\$TEMP_DIR/LFEdge.EVE.API.$EVE_OS_VERSION.nupkg" /"$OUT_FILE"
__EOT__
