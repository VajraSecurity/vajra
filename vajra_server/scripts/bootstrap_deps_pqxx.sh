#!/usr/bin/env bash
# Build vendored third-party dependencies into 3rdparty/local.
# Run once per machine (or after wiping 3rdparty/local). No sudo required.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="$ROOT/3rdparty/local"
RDKAFKA="$ROOT/3rdparty/librdkafka-2.3.0"
PQXX="$ROOT/3rdparty/libpqxx-7.8.1"

if [[ -f "$PREFIX/lib/librdkafka++.a" && -f "$PREFIX/lib/libpqxx.a" ]]; then
    echo "deps already built at $PREFIX — skipping (delete 3rdparty/local to force rebuild)"
    exit 0
fi

if [[ ! -f "$PREFIX/lib/libpqxx.a" ]]; then
    # libpqxx 7.8.1's own cmake/config.cmake calls the internal/undocumented
    # cmake_determine_compile_features(CXX) directly (and includes the module
    # backing it, CMakeDetermineCompileFeatures) -- both removed in CMake 4.x
    # ("Compatibility with CMake < 3.10 will be removed" is the deprecation
    # warning CMake 3.x prints right above that call). On a CMake 4+ host this
    # is a hard configure failure:
    #   CMake Error ... include could not find requested file:
    #     CMakeDetermineCompileFeatures
    #   CMake Error ... Unknown CMake command "cmake_determine_compile_features".
    # That call only ever existed to populate
    # CMAKE_CXX${CMAKE_CXX_STANDARD}_STANDARD_COMPILE_OPTION (config.cmake's
    # one consumer of it, a few lines below) on CMake versions older than
    # 3.10 -- modern CMake already sets that same variable itself, via the
    # per-compiler module (e.g. Modules/Compiler/GNU-CXX.cmake) loaded
    # automatically when `project()` enables CXX, which the `cmake -S ...`
    # configure below does regardless of this patch. Dropping the two lines
    # removes redundant legacy-CMake-support cruft, not a real functional
    # dependency -- this repo's own root CMakeLists.txt already requires
    # CMake >= 3.16, well past the 3.10 floor this shim existed for, and
    # libpqxx's own cmake_minimum_required(VERSION 3.8) confirms it never
    # needed to support anything older than that either. Patches the
    # extracted source in place
    # (never the repo's own files -- 3rdparty/libpqxx-7.8.1/ is fetched
    # fresh by CI on every clean checkout, never committed here,
    # per 3rdparty/libpqxx-*/ in .gitignore) and is idempotent: grep guards
    # it so a second run against an already-patched tree is a no-op.
    CONFIG_CMAKE="$PQXX/cmake/config.cmake"
    if [[ -f "$CONFIG_CMAKE" ]] && grep -q "cmake_determine_compile_features(CXX)" "$CONFIG_CMAKE"; then
        echo "== Patching libpqxx cmake/config.cmake for CMake 4.x compatibility =="
        sed -i \
            -e '/include(CMakeDetermineCompileFeatures)/d' \
            -e '/cmake_determine_compile_features(CXX)/d' \
            "$CONFIG_CMAKE"
    fi

    echo "== Building libpqxx 7.8.1 (static, C++20 to match ABI) =="
    cmake -S "$PQXX" -B "$PQXX/build" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_STANDARD=20 \
        -DBUILD_SHARED_LIBS=OFF \
        -DSKIP_BUILD_TEST=ON \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DPostgreSQL_INCLUDE_DIR=/usr/include/postgresql \
        -DPostgreSQL_LIBRARY=/usr/lib/x86_64-linux-gnu/libpq.so \
        -DCMAKE_INSTALL_PREFIX="$PREFIX"
    cmake --build "$PQXX/build" -j"$(nproc)"
    cmake --install "$PQXX/build"
fi

if [[ -f "$PREFIX/lib/librdkafka++.a" ]]; then
    echo "== librdkafka already built — done =="
    exit 0
fi

# CMakeLists.txt links every target against bare -lrdkafka++/-lrdkafka with
# no path into 3rdparty/local, so it always resolves against the
# system-installed librdkafka-dev package, never this vendored build (unlike
# libpqxx above, which CMakeLists.txt requires vendored via an explicit
# IMPORTED target and a FATAL_ERROR if absent). This vendored librdkafka
# build is therefore optional/vestigial for the actual build -- don't hard
# fail here just because its source tree isn't present (it isn't, in this
# repo's own 3rdparty/ as of this writing; only libpqxx-7.8.1 is vendored).
if [[ ! -d "$RDKAFKA" ]]; then
    echo "== $RDKAFKA not present -- skipping vendored librdkafka build"
    echo "   (CMakeLists.txt links system librdkafka-dev, not this vendored copy, so it's not required)"
    exit 0
fi

echo "== Building librdkafka 2.3.0 (static, SSL + builtin SASL SCRAM/OAUTHBEARER) =="
cmake -S "$RDKAFKA" -B "$RDKAFKA/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DRDKAFKA_BUILD_STATIC=ON \
    -DRDKAFKA_BUILD_EXAMPLES=OFF \
    -DRDKAFKA_BUILD_TESTS=OFF \
    -DWITH_SSL=ON \
    -DWITH_SASL=ON \
    -DWITH_ZLIB=ON \
    -DWITH_ZSTD=OFF \
    -DWITH_CURL=OFF \
    -DENABLE_LZ4_EXT=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_INSTALL_PREFIX="$PREFIX"
cmake --build "$RDKAFKA/build" -j"$(nproc)"
cmake --install "$RDKAFKA/build"
echo "== Done: $PREFIX =="
