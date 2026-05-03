cmake_minimum_required(VERSION 3.22.1)
project(shushhh_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─── Prebuilt static libraries ───
# These must be cross-compiled for arm64-v8a before building.
# Run build_libs.ps1 to compile them, or place prebuilt .a files at:
#   android/app/src/main/cpp/libs/arm64-v8a/

set(LIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ANDROID_ABI})

# libsodium
add_library(sodium STATIC IMPORTED)
set_target_properties(sodium PROPERTIES
    IMPORTED_LOCATION ${LIBS_DIR}/libsodium.a
)

# liboqs (ML-KEM-768 / Kyber)
add_library(oqs STATIC IMPORTED)
set_target_properties(oqs PROPERTIES
    IMPORTED_LOCATION ${LIBS_DIR}/liboqs.a
)

# libcurl (HTTP client for Tor proxy)
add_library(curl_lib STATIC IMPORTED)
set_target_properties(curl_lib PROPERTIES
    IMPORTED_LOCATION ${LIBS_DIR}/libcurl.a
)

# ─── Include directories for prebuilt headers ───
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

# ─── Build the shared native library ───
add_library(shushhh_native SHARED
    jni_bridge.cpp
    tor_manager.cpp
    watchdog_android.cpp
    crypto/crypto.cpp
    auth/auth.cpp
)

target_include_directories(shushhh_native PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${INCLUDE_DIR}
    ${INCLUDE_DIR}/sodium
    ${INCLUDE_DIR}/oqs
    ${INCLUDE_DIR}/curl
    ${INCLUDE_DIR}/nlohmann
)

# Link against prebuilt libs + Android system libs
target_link_libraries(shushhh_native
    sodium
    oqs
    curl_lib
    android
    log
    z        # zlib (provided by NDK, needed by curl)
)

# Compile definitions
target_compile_definitions(shushhh_native PRIVATE
    ANDROID_BUILD=1
)
