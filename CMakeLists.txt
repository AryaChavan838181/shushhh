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

# --- Standalone USB Installer ---
add_executable(shushhh_installer src/installer/Installer.cpp)
if(WIN32)
    # Statically link C++ runtime for portability
    set_property(TARGET shushhh_installer PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
