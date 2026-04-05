#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-x86_64-linux-gnu}"
OPTIMIZE="${OPTIMIZE:-ReleaseFast}"
OUT_PREFIX="zig-out/${TARGET}"
BUILD_EXAMPLES="${BUILD_EXAMPLES:-auto}"
LIBEV_PREFIX="${LIBEV_PREFIX:-}"

mkdir -p "${OUT_PREFIX}/bin" "${OUT_PREFIX}/lib"

if ! command -v zig >/dev/null 2>&1; then
    printf 'error: zig is not installed or not in PATH\n' >&2
    exit 1
fi

ZIG_VERSION="$(zig version)"
case "${ZIG_VERSION}" in
    0.13.*|0.14.*|0.15.*)
        ;;
    *)
        printf 'warning: expected Zig >= 0.13, found %s\n' "${ZIG_VERSION}" >&2
        ;;
esac

printf 'Building ustack for target=%s optimize=%s\n' "${TARGET}" "${OPTIMIZE}"

EXTRA_ARGS=()
if [[ -n "${LIBEV_PREFIX}" ]]; then
    EXTRA_ARGS+=("-Dlibev_prefix=${LIBEV_PREFIX}")
fi

zig build \
    -Dtarget="${TARGET}" \
    -Doptimize="${OPTIMIZE}" \
    "${EXTRA_ARGS[@]}" \
    --prefix "${OUT_PREFIX}"

if [[ "${BUILD_EXAMPLES}" == "auto" ]]; then
    if [[ "${TARGET}" == *"-musl"* ]]; then
        if [[ -f "/usr/local/musl/lib/libev.a" || -f "/usr/local/musl/lib/libev.so" ]]; then
            BUILD_EXAMPLES="1"
        else
            BUILD_EXAMPLES="0"
        fi
    else
        BUILD_EXAMPLES="1"
    fi
fi

if [[ "${BUILD_EXAMPLES}" == "1" ]]; then
    zig build example \
        -Dtarget="${TARGET}" \
        -Doptimize="${OPTIMIZE}" \
        "${EXTRA_ARGS[@]}" \
        --prefix "${OUT_PREFIX}"
else
    printf 'Skipping examples for target=%s (set BUILD_EXAMPLES=1 to force; for musl install libev to /usr/local/musl or set LIBEV_PREFIX)\n' "${TARGET}"
fi

printf '\nBuild complete. Artifacts:\n'
printf '  static lib:  %s\n' "${OUT_PREFIX}/lib/libustack.a"
printf '  shared lib:  %s\n' "${OUT_PREFIX}/lib/libustack.so"
if [[ "${BUILD_EXAMPLES}" == "1" ]]; then
    printf '  examples:    %s\n' "${OUT_PREFIX}/bin/"
fi
printf '\nTip: pass a different target as arg, e.g. ./build_x86_64_linux.sh x86_64-linux-gnu\n'
