cmake_minimum_required(VERSION 3.15)
project(shushhh LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- vcpkg static triplet ---
if(WIN32)
    set(VCPKG_TARGET_TRIPLET "x64-windows-static" CACHE STRING "")
    # Use static MSVC runtime to match static vcpkg libs
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>" CACHE STRING "")
endif()

# --- Dependencies ---
find_package(unofficial-sodium CONFIG REQUIRED)
find_package(CURL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(liboqs CONFIG REQUIRED)
find_package(ftxui CONFIG REQUIRED)

# --- Sources ---
add_executable(shushhh
    Main.cpp
    src/crypto/crypto.cpp
    src/auth/auth.cpp
    src/watchdog/watchdog.cpp
)

target_include_directories(shushhh PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

# --- Link libraries ---
target_link_libraries(shushhh PRIVATE
    unofficial-sodium::sodium
    CURL::libcurl
    nlohmann_json::nlohmann_json
    OQS::oqs
    ftxui::screen
    ftxui::dom
    ftxui::component
)

# --- Windows-specific: static link system libs ---
if(WIN32)
    target_link_libraries(shushhh PRIVATE ws2_32 crypt32 bcrypt)
endif()

# --- Standalone USB Installer (self-contained with embedded binaries) ---
# Generate the .rc content with the path to the built shushhh.exe
set(RC_CONTENT "#include \"resource_ids.h\"\nIDR_SHUSHHH_EXE RCDATA \"$<TARGET_FILE:shushhh>\"\n")
# Check for tor.exe at configure time
if(EXISTS "${CMAKE_SOURCE_DIR}/tor/tor/tor.exe")
    string(APPEND RC_CONTENT "IDR_TOR_EXE RCDATA \"${CMAKE_SOURCE_DIR}/tor/tor/tor.exe\"\n")
    if(EXISTS "${CMAKE_SOURCE_DIR}/tor/data/geoip")
        string(APPEND RC_CONTENT "IDR_TOR_GEOIP RCDATA \"${CMAKE_SOURCE_DIR}/tor/data/geoip\"\n")
    endif()
    if(EXISTS "${CMAKE_SOURCE_DIR}/tor/data/geoip6")
        string(APPEND RC_CONTENT "IDR_TOR_GEOIP6 RCDATA \"${CMAKE_SOURCE_DIR}/tor/data/geoip6\"\n")
    endif()
    message(STATUS "Tor (and data) found — will be embedded in installer")
else()
    message(STATUS "Tor NOT found at ${CMAKE_SOURCE_DIR}/tor/tor/tor.exe — installer will skip Tor")
endif()

file(GENERATE
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/installer_res_$<CONFIG>.rc"
    CONTENT "${RC_CONTENT}"
)

add_executable(shushhh_installer
    src/installer/Installer.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/installer_res_$<CONFIG>.rc"
)
target_include_directories(shushhh_installer PRIVATE ${CMAKE_SOURCE_DIR}/src/installer)
target_link_libraries(shushhh_installer PRIVATE
    ftxui::screen
    ftxui::dom
    ftxui::component
)
add_dependencies(shushhh_installer shushhh)
if(WIN32)
    set_property(TARGET shushhh_installer PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
