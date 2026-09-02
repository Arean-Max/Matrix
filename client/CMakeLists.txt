cmake_minimum_required(VERSION 3.20)
project(event_horizon_client CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DUNICODE -D_UNICODE)

add_library(event_horizon_client_core STATIC
    src/client.cpp
    src/tpm/tpm_subsystem.cpp
    src/session/session_manager.cpp
    src/vm/dual_vm.cpp
    src/vm/cache_sensor.cpp
    src/vm/chaff_machine.cpp
    src/vm/pdata_steganography.cpp
    src/sdk/loader.cpp
)

target_include_directories(event_horizon_client_core PUBLIC
    include
    src
)

target_link_libraries(event_horizon_client_core PUBLIC
    bcrypt
    winhttp
    advapi32
)

add_executable(event_horizon_client_test
    src/main.cpp
)

target_link_libraries(event_horizon_client_test PRIVATE
    event_horizon_client_core
)
