#!/usr/bin/env bash
# Build ONE production benchmark binary (no sanitizer, stripped) and gate on
# vulnerability survival by diffing the .text of the two pair members at the
# chosen opt level.  Emits: <out> (stripped shipped binary) and prints the
# final opt actually used (may step down if the bug did not survive in .text).
#
#   bench_build.sh <root> <target> <opt> <ship_src> <twin_src> <out>
set -uo pipefail
root=$1; target=$2; opt=$3; ship=$4; twin=$5; out=$6

# per-target compiler + cross prefix (production build: NO sanitizer).
case "$target" in
  x86_64)     CC=clang; PFX=llvm- ;;
  macos_arm64)CC=clang; PFX=llvm- ;;
  i686)       CC=i686-linux-gnu-gcc;        PFX=i686-linux-gnu- ;;
  aarch64)    CC=aarch64-linux-gnu-gcc;     PFX=aarch64-linux-gnu- ;;
  armv7hf)    CC=arm-linux-gnueabihf-gcc;   PFX=arm-linux-gnueabihf- ;;
  riscv64)    CC=riscv64-linux-gnu-gcc;     PFX=riscv64-linux-gnu- ;;
  mips32be)   CC=mips-linux-gnu-gcc;        PFX=mips-linux-gnu- ;;
  mips32le)   CC=mipsel-linux-gnu-gcc;      PFX=mipsel-linux-gnu- ;;
  mips64le)   G=$HOME/mips-sanitizer-runtime/gcc12-mips64el-root
              CC=$G/bin/mips64el-linux-gnuabi64-gcc
              PFX=$G/binutils-shim/
              EXTRAF="-B$G/binutils-shim/ -B/usr/mips64el-linux-gnuabi64/lib/" ;;
  ppc32be)    CC=powerpc-linux-gnu-gcc;     PFX=powerpc-linux-gnu- ;;
  *) echo "unknown target $target" >&2; exit 2 ;;
esac
EXTRAF=${EXTRAF:-}
OBJCOPY=${PFX}objcopy; STRIP=${PFX}strip
command -v "$OBJCOPY" >/dev/null 2>&1 || OBJCOPY=objcopy
command -v "$STRIP"   >/dev/null 2>&1 || STRIP=strip

optflags() { case "$1" in O0)echo "-O0";;O1)echo "-O1";;O2)echo "-O2";;O3)echo "-O3";;LTO)echo "-O3 -flto";;esac; }
BASE="-std=gnu11 -DNDEBUG -fomit-frame-pointer -fno-ident -w"

textsec() { # extract .text (or __text) bytes of $1 to $2, portable
  if command -v "$OBJCOPY" >/dev/null 2>&1; then
    if "$OBJCOPY" -O binary --only-section=.text "$1" "$2" 2>/dev/null && [ -s "$2" ]; then return 0; fi
    "$OBJCOPY" -O binary --only-section=__text "$1" "$2" 2>/dev/null && [ -s "$2" ] && return 0
  fi
  if command -v otool >/dev/null 2>&1; then       # macOS Mach-O
    otool -s __TEXT __text "$1" 2>/dev/null | sed 1d > "$2" && [ -s "$2" ] && return 0
  fi
  cp "$1" "$2"
}

order="$opt O3 O2 O1 O0"; seen=" "
final=
for o in $order; do
  case "$seen" in *" $o "*) continue;; esac; seen="$seen$o "
  fl=$(optflags "$o")
  sb=$(mktemp); tb=$(mktemp)
  if ! $CC $BASE $fl $EXTRAF -I "$root/include" "$root/src/$ship" -o "$sb" -lm 2>/dev/null; then rm -f "$sb" "$tb"; continue; fi
  if ! $CC $BASE $fl $EXTRAF -I "$root/include" "$root/src/$twin" -o "$tb" -lm 2>/dev/null; then rm -f "$sb" "$tb"; continue; fi
  "$STRIP" "$sb" 2>/dev/null; "$STRIP" "$tb" 2>/dev/null
  st=$(mktemp); tt=$(mktemp); textsec "$sb" "$st"; textsec "$tb" "$tt"
  if ! cmp -s "$st" "$tt"; then
    cp "$sb" "$out"; final=$o; rm -f "$sb" "$tb" "$st" "$tt"; break
  fi
  rm -f "$sb" "$tb" "$st" "$tt"
done
[ -n "$final" ] && echo "$final" || { echo "SURVIVE_FAIL" >&2; exit 3; }
