# ============================================================
# build_libs.ps1 — Cross-compile dependencies for Android arm64-v8a
# ============================================================
# Builds libsodium, liboqs, and libcurl as static libraries for
# the Android NDK arm64-v8a target using Ninja.
#
# Prerequisites:
# - Android SDK with NDK and CMake installed (via Android Studio)
# - Git installed
#
# Usage:
#   .\build_libs.ps1

param(
    [string]$NdkPath = ""
)

$ErrorActionPreference = "Continue"

# ── Find Android NDK ──
if (-not $NdkPath) {
    $sdkPath = "$env:LOCALAPPDATA\Android\Sdk"
    if (Test-Path "$sdkPath\ndk") {
        $ndkVersions = Get-ChildItem "$sdkPath\ndk" | Sort-Object Name -Descending
        if ($ndkVersions.Count -gt 0) {
            $NdkPath = $ndkVersions[0].FullName
        }
    }
}

if (-not $NdkPath -or -not (Test-Path $NdkPath)) {
    Write-Error "Android NDK not found. Set -NdkPath or install via Android Studio."
    exit 1
}

Write-Host "Using NDK: $NdkPath" -ForegroundColor Cyan

$TOOLCHAIN = "$NdkPath\build\cmake\android.toolchain.cmake"
$ABI = "arm64-v8a"
$API = 26
$BUILD_TYPE = "Release"

# ── Find SDK CMake + Ninja ──
$SDK_CMAKE_DIR = "$env:LOCALAPPDATA\Android\Sdk\cmake\3.22.1\bin"
if (Test-Path "$SDK_CMAKE_DIR\cmake.exe") {
    $CMAKE_EXE = "$SDK_CMAKE_DIR\cmake.exe"
    Write-Host "Using SDK cmake: $CMAKE_EXE" -ForegroundColor Cyan
} else {
    $CMAKE_EXE = "cmake"
    Write-Host "Using system cmake" -ForegroundColor Yellow
}

# Ensure ninja is on PATH (SDK cmake dir has it)
if (Test-Path "$SDK_CMAKE_DIR\ninja.exe") {
    $env:PATH = "$SDK_CMAKE_DIR;$env:PATH"
    Write-Host "Added SDK ninja to PATH" -ForegroundColor Cyan
}

$PROJECT_DIR = Split-Path -Parent $PSScriptRoot
$CPP_DIR = "$PROJECT_DIR\android\app\src\main\cpp"
$LIBS_DIR = "$CPP_DIR\libs\arm64-v8a"
$INCLUDE_DIR = "$CPP_DIR\include"
# Use a SHORT path for build directory to avoid Windows MAX_PATH issues
# (Ninja depfile paths get extremely long with the full project path)
$BUILD_DIR = "C:\shushhh_bd"

New-Item -ItemType Directory -Force -Path $LIBS_DIR, $INCLUDE_DIR, $BUILD_DIR | Out-Null

# ── NDK clang for direct compilation ──
$NDK_TOOLCHAIN_DIR = "$NdkPath\toolchains\llvm\prebuilt\windows-x86_64\bin"
$CC = "$NDK_TOOLCHAIN_DIR\aarch64-linux-android${API}-clang.cmd"
$AR = "$NDK_TOOLCHAIN_DIR\llvm-ar.exe"
$RANLIB = "$NDK_TOOLCHAIN_DIR\llvm-ranlib.exe"

if (-not (Test-Path $CC)) {
    # Try without .cmd extension
    $CC = "$NDK_TOOLCHAIN_DIR\aarch64-linux-android${API}-clang"
}

# ============================================================
# 1. Build libsodium (direct compilation — no CMakeLists.txt)
# ============================================================
Write-Host "`n═══ Building libsodium ═══" -ForegroundColor Green

$SODIUM_DIR = "$BUILD_DIR\libsodium"
if (-not (Test-Path $SODIUM_DIR)) {
    git clone --depth 1 --branch stable https://github.com/jedisct1/libsodium.git $SODIUM_DIR
}

# Use the pre-written CMakeLists.txt wrapper for libsodium
$SODIUM_CMAKE_DIR = "$BUILD_DIR\libsodium-cmake"
New-Item -ItemType Directory -Force -Path $SODIUM_CMAKE_DIR | Out-Null

# Copy the wrapper CMakeLists.txt from the android directory to the short build dir
$wrapperSrc = "$PSScriptRoot\build_deps\libsodium-cmake\CMakeLists.txt"
if (-not (Test-Path $wrapperSrc)) {
    # Also try the project directory (first run)
    $wrapperSrc = "$PROJECT_DIR\android\build_deps\libsodium-cmake\CMakeLists.txt"
}
if (-not (Test-Path $wrapperSrc)) {
    Write-Host "[-] libsodium CMakeLists.txt wrapper not found" -ForegroundColor Red
    exit 1
}
Copy-Item $wrapperSrc "$SODIUM_CMAKE_DIR\CMakeLists.txt" -Force
Write-Host "[*] Using libsodium CMake wrapper"

# Also generate version.h from the template
$versionHIn = "$SODIUM_DIR\src\libsodium\include\sodium\version.h.in"
$versionHOut = "$SODIUM_DIR\src\libsodium\include\sodium\version.h"

if ((Test-Path $versionHIn) -and -not (Test-Path $versionHOut)) {
    $versionContent = Get-Content $versionHIn -Raw
    $versionContent = $versionContent -replace '@VERSION@', '1.0.20'
    $versionContent = $versionContent -replace '@SODIUM_LIBRARY_VERSION_MAJOR@', '26'
    $versionContent = $versionContent -replace '@SODIUM_LIBRARY_VERSION_MINOR@', '2'
    $versionContent = $versionContent -replace '@SODIUM_LIBRARY_MINIMAL_DEF@', ''
    $versionContent | Set-Content $versionHOut -Encoding UTF8
    Write-Host "[*] Generated version.h"
}

$SODIUM_BUILD = "$BUILD_DIR\libsodium-build"
if (Test-Path $SODIUM_BUILD) { Remove-Item -Recurse -Force $SODIUM_BUILD }
New-Item -ItemType Directory -Force -Path $SODIUM_BUILD | Out-Null

& $CMAKE_EXE -B $SODIUM_BUILD -S $SODIUM_CMAKE_DIR `
    -G Ninja `
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" `
    -DANDROID_ABI="$ABI" `
    -DANDROID_PLATFORM="android-28" `
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE"

if ($LASTEXITCODE -ne 0) { Write-Host "[-] libsodium cmake configure FAILED" -ForegroundColor Red; exit 1 }

& $CMAKE_EXE --build $SODIUM_BUILD --config $BUILD_TYPE -j8

if ($LASTEXITCODE -ne 0) { Write-Host "[-] libsodium build FAILED" -ForegroundColor Red; exit 1 }

# Copy outputs
Get-ChildItem -Recurse "$SODIUM_BUILD" -Filter "libsodium.a" | Select-Object -First 1 | Copy-Item -Destination "$LIBS_DIR\" -Force
New-Item -ItemType Directory -Force -Path "$INCLUDE_DIR\sodium" | Out-Null
Copy-Item "$SODIUM_DIR\src\libsodium\include\sodium.h" "$INCLUDE_DIR\" -Force
Copy-Item "$SODIUM_DIR\src\libsodium\include\sodium\*" "$INCLUDE_DIR\sodium\" -Force -Recurse

if (Test-Path "$LIBS_DIR\libsodium.a") {
    Write-Host "[+] libsodium built successfully" -ForegroundColor Green
} else {
    Write-Host "[-] libsodium.a not found!" -ForegroundColor Red
    exit 1
}

# ============================================================
# 2. Build liboqs
# ============================================================
Write-Host "`n═══ Building liboqs ═══" -ForegroundColor Green

$OQS_DIR = "$BUILD_DIR\liboqs"
if (-not (Test-Path $OQS_DIR)) {
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git $OQS_DIR
}

$OQS_BUILD = "$BUILD_DIR\liboqs-build"
if (Test-Path $OQS_BUILD) { Remove-Item -Recurse -Force $OQS_BUILD }
New-Item -ItemType Directory -Force -Path $OQS_BUILD | Out-Null

& $CMAKE_EXE -B $OQS_BUILD -S $OQS_DIR `
    -G Ninja `
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" `
    -DANDROID_ABI="$ABI" `
    -DANDROID_PLATFORM="android-$API" `
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" `
    -DBUILD_SHARED_LIBS=OFF `
    -DOQS_BUILD_ONLY_LIB=ON `
    -DOQS_USE_OPENSSL=OFF `
    -DOQS_MINIMAL_BUILD="KEM_ml_kem_768"

if ($LASTEXITCODE -ne 0) { Write-Host "[-] liboqs cmake configure FAILED" -ForegroundColor Red; exit 1 }

& $CMAKE_EXE --build $OQS_BUILD --config $BUILD_TYPE -j8

if ($LASTEXITCODE -ne 0) { Write-Host "[-] liboqs build FAILED" -ForegroundColor Red; exit 1 }

# Copy outputs
Get-ChildItem -Recurse "$OQS_BUILD" -Filter "liboqs.a" | Select-Object -First 1 | Copy-Item -Destination "$LIBS_DIR\" -Force
New-Item -ItemType Directory -Force -Path "$INCLUDE_DIR\oqs" | Out-Null
# Headers are generated in the build tree at include/oqs/
Copy-Item "$OQS_BUILD\include\oqs\*.h" "$INCLUDE_DIR\oqs\" -Force

if (Test-Path "$LIBS_DIR\liboqs.a") {
    Write-Host "[+] liboqs built successfully" -ForegroundColor Green
} else {
    Write-Host "[-] liboqs.a not found!" -ForegroundColor Red
    exit 1
}

# ============================================================
# 3. Build libcurl (minimal, with SOCKS5 support)
# ============================================================
Write-Host "`n═══ Building libcurl ═══" -ForegroundColor Green

$CURL_DIR = "$BUILD_DIR\curl"
if (-not (Test-Path $CURL_DIR)) {
    git clone --depth 1 --branch curl-8_7_1 https://github.com/curl/curl.git $CURL_DIR
}

$CURL_BUILD = "$BUILD_DIR\curl-build"
if (Test-Path $CURL_BUILD) { Remove-Item -Recurse -Force $CURL_BUILD }
New-Item -ItemType Directory -Force -Path $CURL_BUILD | Out-Null

& $CMAKE_EXE -B $CURL_BUILD -S $CURL_DIR `
    -G Ninja `
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" `
    -DANDROID_ABI="$ABI" `
    -DANDROID_PLATFORM="android-$API" `
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" `
    -DBUILD_SHARED_LIBS=OFF `
    -DBUILD_CURL_EXE=OFF `
    -DCURL_USE_OPENSSL=OFF `
    -DCURL_USE_MBEDTLS=OFF `
    -DCURL_USE_WOLFSSL=OFF `
    -DCURL_DISABLE_LDAP=ON `
    -DCURL_DISABLE_TELNET=ON `
    -DCURL_DISABLE_DICT=ON `
    -DCURL_DISABLE_FILE=ON `
    -DCURL_DISABLE_TFTP=ON `
    -DCURL_DISABLE_RTSP=ON `
    -DCURL_DISABLE_POP3=ON `
    -DCURL_DISABLE_IMAP=ON `
    -DCURL_DISABLE_SMTP=ON `
    -DCURL_DISABLE_GOPHER=ON `
    -DCURL_DISABLE_MQTT=ON `
    -DHTTP_ONLY=ON `
    -DENABLE_UNIX_SOCKETS=ON

if ($LASTEXITCODE -ne 0) { Write-Host "[-] libcurl cmake configure FAILED" -ForegroundColor Red; exit 1 }

& $CMAKE_EXE --build $CURL_BUILD --config $BUILD_TYPE -j8

if ($LASTEXITCODE -ne 0) { Write-Host "[-] libcurl build FAILED" -ForegroundColor Red; exit 1 }

# Copy outputs
Get-ChildItem -Recurse "$CURL_BUILD" -Filter "libcurl.a" | Select-Object -First 1 | Copy-Item -Destination "$LIBS_DIR\" -Force
New-Item -ItemType Directory -Force -Path "$INCLUDE_DIR\curl" | Out-Null
Copy-Item "$CURL_DIR\include\curl\*.h" "$INCLUDE_DIR\curl\" -Force

if (Test-Path "$LIBS_DIR\libcurl.a") {
    Write-Host "[+] libcurl built successfully" -ForegroundColor Green
} else {
    Write-Host "[-] libcurl.a not found!" -ForegroundColor Red
    exit 1
}

# ============================================================
# 4. Copy nlohmann/json (header-only)
# ============================================================
Write-Host "`n═══ Downloading nlohmann/json ═══" -ForegroundColor Green

$JSON_HEADER = "$INCLUDE_DIR\nlohmann\json.hpp"
New-Item -ItemType Directory -Force -Path "$INCLUDE_DIR\nlohmann" | Out-Null

if (-not (Test-Path $JSON_HEADER)) {
    Invoke-WebRequest -Uri "https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp" `
        -OutFile $JSON_HEADER -UseBasicParsing
}

Write-Host "[+] nlohmann/json downloaded" -ForegroundColor Green

# ============================================================
# Summary
# ============================================================
Write-Host "`n═══════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Build complete!" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════" -ForegroundColor Cyan
Write-Host "Libraries: $LIBS_DIR"
Write-Host "Headers:   $INCLUDE_DIR"
Get-ChildItem $LIBS_DIR -Filter "*.a" | ForEach-Object { Write-Host "  [+] $($_.Name) ($([math]::Round($_.Length/1KB, 1)) KB)" -ForegroundColor Green }
