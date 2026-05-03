# ============================================================
# download_tor.ps1 — Download Tor Expert Bundle for Android
# ============================================================
$ErrorActionPreference = "Stop"

$TOR_VERSION = "15.0.11"
$ASSETS_DIR = "$PSScriptRoot\app\src\main\assets\tor"
$JNILIBS_DIR = "$PSScriptRoot\app\src\main\jniLibs"
$TEMP_DIR = "$PSScriptRoot\build_deps\tor_download"

Write-Host "═══ Downloading Tor Expert Bundle ═══" -ForegroundColor Green
Write-Host "Version: $TOR_VERSION"

New-Item -ItemType Directory -Force -Path $ASSETS_DIR, $TEMP_DIR | Out-Null

$ARCHS = @{
    "aarch64" = "arm64-v8a";
    "armv7"   = "armeabi-v7a";
    "x86"     = "x86";
    "x86_64"  = "x86_64"
}

foreach ($arch_key in $ARCHS.Keys) {
    $arch_mapped = $ARCHS[$arch_key]
    $url = "https://dist.torproject.org/torbrowser/$TOR_VERSION/tor-expert-bundle-android-$arch_key-$TOR_VERSION.tar.gz"
    $tar_file = "$TEMP_DIR\tor-$arch_key.tar.gz"
    $ext_dir = "$TEMP_DIR\ext_$arch_key"
    
    Write-Host "[*] Processing $arch_key -> libTor-${arch_mapped}.so ..."
    
    if (-not (Test-Path $tar_file)) {
        Invoke-WebRequest -Uri $url -OutFile $tar_file -UseBasicParsing
    }
    
    New-Item -ItemType Directory -Force -Path $ext_dir | Out-Null
    tar -xzf $tar_file -C $ext_dir
    
    $bin_path = "$ext_dir\tor\libTor.so"
    if (-not (Test-Path $bin_path)) { $bin_path = "$ext_dir\tor\tor" }
    
    if (Test-Path $bin_path) {
        $abi_dir = "$JNILIBS_DIR\${arch_mapped}"
        New-Item -ItemType Directory -Force -Path $abi_dir | Out-Null
        Copy-Item -Path $bin_path -Destination "$abi_dir\libTor.so" -Force
        Write-Host "    [+] Saved $abi_dir\libTor.so" -ForegroundColor Cyan
        
        # Only copy geoip from one of them
        if ($arch_key -eq "aarch64") {
            Copy-Item -Path "$ext_dir\data\geoip" -Destination "$ASSETS_DIR\geoip" -Force
            Copy-Item -Path "$ext_dir\data\geoip6" -Destination "$ASSETS_DIR\geoip6" -Force
            Copy-Item -Path "$ext_dir\data\torrc-defaults" -Destination "$ASSETS_DIR\torrc-defaults" -Force
        }
    } else {
        Write-Host "    [-] Failed to find tor binary in tar" -ForegroundColor Red
    }
}

Write-Host "Cleaning up temporary files..."
Remove-Item -Path $TEMP_DIR -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Done! All architectures downloaded and packaged." -ForegroundColor Green
