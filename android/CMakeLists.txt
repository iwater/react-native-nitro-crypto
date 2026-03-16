cmake_minimum_required(VERSION 3.9.0)
project(RNNodeCrypto)

set(PACKAGE_NAME RNNodeCrypto)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)

# Add our custom implementation and JNI adapter
add_library(${PACKAGE_NAME} SHARED
        ../cpp/HybridNodeCrypto.cpp
        OnLoad.cpp
)

# Force both hash styles (sysv and gnu) for Android loader compatibility
target_link_options(${PACKAGE_NAME} PRIVATE "-Wl,--hash-style=both")

# Include paths for our headers
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../cpp
)

# Include the Nitrogen-generated CMake file
include(${CMAKE_CURRENT_SOURCE_DIR}/../nitrogen/generated/android/RNNodeCrypto+autolinking.cmake)

# Import Prebuilt Rust Library
target_link_directories(${PACKAGE_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ANDROID_ABI})

# Link libraries
target_link_libraries(${PACKAGE_NAME}
        rn_node_crypto
        log
)

# Android 15 16KB page size alignment
if(ANDROID_ABI STREQUAL "arm64-v8a" OR ANDROID_ABI STREQUAL "x86_64")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,max-page-size=16384")
endif()
