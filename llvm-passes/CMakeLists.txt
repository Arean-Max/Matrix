cmake_minimum_required(VERSION 3.20)
project(event_horizon_llvm_passes CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

add_library(EventHorizonPasses MODULE
    src/QuasigroupMBAPass.cpp
    src/SymbolicExplosionPass.cpp
    src/DualVMCompilerPass.cpp
    src/PDataSteganographyPass.cpp
    src/PluginRegistration.cpp
)

target_include_directories(EventHorizonPasses PRIVATE
    include
)
