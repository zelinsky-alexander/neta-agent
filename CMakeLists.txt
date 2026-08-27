cmake_minimum_required(VERSION 3.20)
project(neta-agent VERSION 0.1.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "POC1 implements only the Linux backend. The core model is platform-neutral by design.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(NETA_ENABLE_TESTS "Build tests" ON)
option(NETA_STATIC_DEPS "Prefer static OpenSSL/SQLite and static C++ runtime when available" OFF)
option(NETA_FULL_STATIC "Request a fully static executable (intended for musl release builds)" OFF)

if(NETA_STATIC_DEPS)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

find_package(OpenSSL 3.0 REQUIRED)
find_package(SQLite3 REQUIRED)

add_library(neta_core
    src/core/model.cpp
    src/core/crypto.cpp
    src/core/verdict.cpp
    src/core/tls_probe.cpp
    src/core/history_store.cpp
    src/platform/linux/environment.cpp
    src/platform/linux/socket_diag.cpp
    src/platform/linux/process_resolver.cpp
    src/platform/linux/route_observer.cpp
)

target_include_directories(neta_core PUBLIC include)
target_link_libraries(neta_core PUBLIC OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)
target_compile_options(neta_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)

add_executable(neta-agent src/main.cpp)
target_link_libraries(neta-agent PRIVATE neta_core)
target_compile_options(neta-agent PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)

if(NETA_STATIC_DEPS)
    target_link_options(neta-agent PRIVATE -static-libgcc -static-libstdc++)
endif()
if(NETA_FULL_STATIC)
    target_link_options(neta-agent PRIVATE -static)
endif()

if(NETA_ENABLE_TESTS)
    enable_testing()
    add_executable(neta_tests tests/tests.cpp)
    target_link_libraries(neta_tests PRIVATE neta_core)
    target_compile_options(neta_tests PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    add_test(NAME neta_tests COMMAND neta_tests)
endif()
