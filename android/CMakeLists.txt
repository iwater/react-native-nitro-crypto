cmake_minimum_required(VERSION 3.10)

# Project Name - matches androidCxxLibName in nitro.json
project(RNNodeCrypto)

# Use C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Import Prebuilt Rust Library
add_library(rn_node_crypto SHARED IMPORTED)
set_target_properties(rn_node_crypto PROPERTIES IMPORTED_LOCATION
        "${CMAKE_CURRENT_SOURCE_DIR}/libs/${ANDROID_ABI}/librn_node_crypto.so")

# Helper function to find all sources in a directory
function(find_all_sources TARGET_VAR DIRECTORY)
    file(GLOB_RECURSE SOURCES "${DIRECTORY}/*.cpp" "${DIRECTORY}/*.hpp" "${DIRECTORY}/*.h")
    set(${TARGET_VAR} ${SOURCES} PARENT_SCOPE)
endfunction()

# 1. Define source directories
set(CPP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../cpp")
set(NITROGEN_ANDROID_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../nitrogen/generated/android/c++")
set(NITROGEN_SHARED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../nitrogen/generated/shared/c++")

# 2. Collect sources
find_all_sources(CPP_SOURCES "${CPP_DIR}")
find_all_sources(NITROGEN_ANDROID_SOURCES "${NITROGEN_ANDROID_DIR}")
find_all_sources(NITROGEN_SHARED_SOURCES "${NITROGEN_SHARED_DIR}")

# 3. Create the Main Library (JNI bridge)
add_library(RNNodeCrypto SHARED
        ${CPP_SOURCES}
        ${NITROGEN_ANDROID_SOURCES}
        ${NITROGEN_SHARED_SOURCES}
)

# 4. Find Dependencies
find_package(ReactAndroid REQUIRED CONFIG)
find_package(fbjni REQUIRED CONFIG)
find_package(NitroModules REQUIRED CONFIG)

# 5. Link Libraries
target_link_libraries(RNNodeCrypto
        PRIVATE
        ReactAndroid::jsi
        fbjni::fbjni
        NitroModules::NitroModules
        rn_node_crypto # Link against the Rust library
        log
)

# 6. Include Directories
target_include_directories(RNNodeCrypto PUBLIC
        "${CPP_DIR}"
        "${NITROGEN_ANDROID_DIR}"
        "${NITROGEN_SHARED_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../rust_c_crypto/include" # For rn_node_crypto.h if needed
)
