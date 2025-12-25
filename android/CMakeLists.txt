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
