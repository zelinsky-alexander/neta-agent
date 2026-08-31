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
option(NETA_BUILD_TLS_CONTEXT_SHIM "Build opt-in OpenSSL actual-session instrumentation shim" ON)
set(NETA_EBPF "AUTO" CACHE STRING "Build lifecycle/application-context eBPF support: AUTO, ON, or OFF")
set_property(CACHE NETA_EBPF PROPERTY STRINGS AUTO ON OFF)
if(NOT NETA_EBPF MATCHES "^(AUTO|ON|OFF)$")
    message(FATAL_ERROR "NETA_EBPF must be AUTO, ON, or OFF")
endif()

if(NETA_STATIC_DEPS)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

find_package(OpenSSL 3.0 REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

set(NETA_HAVE_EBPF FALSE)
if(NOT NETA_EBPF STREQUAL "OFF")
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBBPF QUIET IMPORTED_TARGET libbpf)
    endif()
    find_program(NETA_CLANG_EXECUTABLE NAMES clang)
    if(LIBBPF_FOUND AND NETA_CLANG_EXECUTABLE)
        file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles")
        file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/neta_bpf_compiler_check.c" "int x;\n")
        execute_process(
            COMMAND "${NETA_CLANG_EXECUTABLE}" -target bpf -c
                    "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/neta_bpf_compiler_check.c"
                    -o "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/neta_bpf_compiler_check.o"
            RESULT_VARIABLE NETA_BPF_COMPILER_RESULT
            OUTPUT_QUIET ERROR_QUIET
        )
        if(NETA_BPF_COMPILER_RESULT EQUAL 0)
            set(NETA_HAVE_EBPF TRUE)
        endif()
    elseif(NETA_EBPF STREQUAL "ON")
        message(FATAL_ERROR "NETA_EBPF=ON requires clang and libbpf development files")
    endif()
    if(NETA_EBPF STREQUAL "ON" AND NOT NETA_HAVE_EBPF)
        message(FATAL_ERROR "NETA_EBPF=ON requires a clang compiler with the BPF target")
    endif()
    if(NETA_EBPF STREQUAL "AUTO" AND NOT NETA_HAVE_EBPF)
        message(STATUS "eBPF build support unavailable; building polling/context fallback")
    endif()
endif()

set(NETA_PLATFORM_SOURCES
    src/platform/linux/environment.cpp
    src/platform/linux/host_network_environment.cpp
    src/platform/linux/socket_diag.cpp
    src/platform/linux/process_resolver.cpp
    src/platform/linux/route_observer.cpp
    src/platform/linux/ebpf/lifecycle_decoder.cpp
    src/platform/linux/ebpf/name_resolution_decoder.cpp
    src/platform/linux/tls_session_decoder.cpp
    src/platform/linux/tls_session_observer.cpp
)

if(NETA_HAVE_EBPF)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
        set(NETA_BPF_ARCH x86)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
        set(NETA_BPF_ARCH arm64)
    else()
        message(FATAL_ERROR "eBPF currently supports x86_64 and arm64 release targets")
    endif()

    set(NETA_BPF_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/linux/ebpf")
    set(NETA_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
    file(MAKE_DIRECTORY "${NETA_GENERATED_DIR}")
    set(NETA_BPF_INCLUDE_ARGS "-I${NETA_BPF_DIR}" -I/usr/include)
    if(CMAKE_LIBRARY_ARCHITECTURE)
        list(APPEND NETA_BPF_INCLUDE_ARGS "-I/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}")
    endif()

    set(NETA_LIFECYCLE_BPF_OBJECT "${NETA_GENERATED_DIR}/lifecycle.bpf.o")
    set(NETA_LIFECYCLE_BPF_BYTES "${NETA_GENERATED_DIR}/lifecycle_bpf_bytes.inc")
    add_custom_command(
        OUTPUT "${NETA_LIFECYCLE_BPF_OBJECT}"
        COMMAND "${NETA_CLANG_EXECUTABLE}" -g -O2 -target bpf
                "-fdebug-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=."
                -D__TARGET_ARCH_${NETA_BPF_ARCH} ${NETA_BPF_INCLUDE_ARGS}
                -c "${NETA_BPF_DIR}/lifecycle.bpf.c" -o "${NETA_LIFECYCLE_BPF_OBJECT}"
        DEPENDS
            "${NETA_BPF_DIR}/lifecycle.bpf.c"
            "${NETA_BPF_DIR}/lifecycle_wire.h"
            "${NETA_BPF_DIR}/vmlinux_min.h"
        VERBATIM
    )
    add_custom_command(
        OUTPUT "${NETA_LIFECYCLE_BPF_BYTES}"
        COMMAND "${CMAKE_COMMAND}" "-DINPUT=${NETA_LIFECYCLE_BPF_OBJECT}"
                "-DOUTPUT=${NETA_LIFECYCLE_BPF_BYTES}" "-DSYMBOL=Lifecycle"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/EmbedBinary.cmake"
        DEPENDS "${NETA_LIFECYCLE_BPF_OBJECT}"
                "${CMAKE_CURRENT_SOURCE_DIR}/cmake/EmbedBinary.cmake"
        VERBATIM
    )

    set(NETA_NAME_RESOLUTION_BPF_OBJECT "${NETA_GENERATED_DIR}/name_resolution.bpf.o")
    set(NETA_NAME_RESOLUTION_BPF_BYTES "${NETA_GENERATED_DIR}/name_resolution_bpf_bytes.inc")
    add_custom_command(
        OUTPUT "${NETA_NAME_RESOLUTION_BPF_OBJECT}"
        COMMAND "${NETA_CLANG_EXECUTABLE}" -g -O2 -target bpf
                "-fdebug-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=."
                -D__TARGET_ARCH_${NETA_BPF_ARCH} ${NETA_BPF_INCLUDE_ARGS}
                -c "${NETA_BPF_DIR}/name_resolution.bpf.c"
                -o "${NETA_NAME_RESOLUTION_BPF_OBJECT}"
        DEPENDS
            "${NETA_BPF_DIR}/name_resolution.bpf.c"
            "${NETA_BPF_DIR}/name_resolution_wire.h"
            "${NETA_BPF_DIR}/vmlinux_min.h"
        VERBATIM
    )
    add_custom_command(
        OUTPUT "${NETA_NAME_RESOLUTION_BPF_BYTES}"
        COMMAND "${CMAKE_COMMAND}" "-DINPUT=${NETA_NAME_RESOLUTION_BPF_OBJECT}"
                "-DOUTPUT=${NETA_NAME_RESOLUTION_BPF_BYTES}" "-DSYMBOL=NameResolution"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/EmbedBinary.cmake"
        DEPENDS "${NETA_NAME_RESOLUTION_BPF_OBJECT}"
                "${CMAKE_CURRENT_SOURCE_DIR}/cmake/EmbedBinary.cmake"
        VERBATIM
    )

    set_source_files_properties(src/platform/linux/ebpf/lifecycle_loader.cpp
        PROPERTIES OBJECT_DEPENDS "${NETA_LIFECYCLE_BPF_BYTES}")
    set_source_files_properties(src/platform/linux/ebpf/name_resolution_loader.cpp
        PROPERTIES OBJECT_DEPENDS "${NETA_NAME_RESOLUTION_BPF_BYTES}")
    list(APPEND NETA_PLATFORM_SOURCES
         src/platform/linux/ebpf/lifecycle_loader.cpp
         src/platform/linux/ebpf/name_resolution_loader.cpp)
else()
    list(APPEND NETA_PLATFORM_SOURCES
         src/platform/linux/ebpf/lifecycle_loader_stub.cpp
         src/platform/linux/ebpf/name_resolution_loader_stub.cpp)
endif()

add_library(neta_core
    src/core/model.cpp
    src/core/name_resolution.cpp
    src/core/tls_session.cpp
    src/core/connection_direction.cpp
    src/core/route_semantics.cpp
    src/core/tcp_state.cpp
    src/core/lifecycle.cpp
    src/core/crypto.cpp
    src/core/verdict.cpp
    src/core/tls_probe.cpp
    src/core/history_store.cpp
    src/core/history_environment.cpp
    src/core/history_name_resolution.cpp
    src/core/history_tls_session.cpp
    src/core/history_schema.cpp
    src/core/history_maintenance.cpp
    src/core/connection_admission.cpp
    src/core/connection_filter.cpp
    src/core/connection_admission_policy.cpp
    src/core/connection_tracker.cpp
    src/core/observation_session.cpp
    src/core/evidence_scheduler.cpp
    src/core/storage_maintenance.cpp
    src/cli/observation_options.cpp
    src/cli/observation_command.cpp
    ${NETA_PLATFORM_SOURCES}
)

target_include_directories(neta_core PUBLIC include PRIVATE src/platform/linux src/platform/linux/ebpf)
target_link_libraries(neta_core PUBLIC OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3 ${CMAKE_DL_LIBS})
if(NETA_HAVE_EBPF)
    target_include_directories(neta_core PRIVATE "${NETA_GENERATED_DIR}")
    target_link_libraries(neta_core PRIVATE PkgConfig::LIBBPF)
endif()
target_compile_options(neta_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)

set(NETA_TLS_CONTEXT_SHIM_BUILT FALSE)
if(NETA_BUILD_TLS_CONTEXT_SHIM AND NOT NETA_STATIC_DEPS AND NOT NETA_FULL_STATIC)
    add_library(neta_tls_context SHARED src/platform/linux/tls_context_shim.cpp)
    set_target_properties(neta_tls_context PROPERTIES OUTPUT_NAME neta_tls_context)
    target_include_directories(neta_tls_context PRIVATE src/platform/linux)
    target_link_libraries(neta_tls_context PRIVATE OpenSSL::SSL OpenSSL::Crypto
                                                    ${CMAKE_DL_LIBS} Threads::Threads)
    target_compile_options(neta_tls_context PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    set(NETA_TLS_CONTEXT_SHIM_BUILT TRUE)
    target_compile_definitions(neta_core PRIVATE NETA_TLS_CONTEXT_SHIM_BUILT=1)
else()
    message(STATUS "OpenSSL TLS context shim disabled for this build")
endif()

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
    target_include_directories(neta_tests PRIVATE src/platform/linux/ebpf)
    target_compile_options(neta_tests PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    add_test(NAME neta_tests COMMAND neta_tests)

    add_executable(neta_ms0_tests tests/ms0_tests.cpp)
    target_link_libraries(neta_ms0_tests PRIVATE neta_core)
    target_compile_options(neta_ms0_tests PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    add_test(NAME neta_ms0_tests COMMAND neta_ms0_tests)

    add_executable(neta_ms1_tests tests/ms1_tests.cpp)
    target_link_libraries(neta_ms1_tests PRIVATE neta_core)
    target_include_directories(neta_ms1_tests PRIVATE src/platform/linux/ebpf)
    target_compile_options(neta_ms1_tests PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    add_test(NAME neta_ms1_tests COMMAND neta_ms1_tests)

    add_executable(neta_ms1_ebpf_integration tests/ms1_ebpf_integration.cpp)
    target_link_libraries(neta_ms1_ebpf_integration PRIVATE neta_core)
    target_compile_options(neta_ms1_ebpf_integration PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    add_test(NAME neta_ms1_ebpf_integration COMMAND neta_ms1_ebpf_integration)
    set_tests_properties(neta_ms1_ebpf_integration PROPERTIES SKIP_RETURN_CODE 77)

    add_executable(neta_history_cli_test tests/history_cli_test.cpp)
    target_link_libraries(neta_history_cli_test PRIVATE neta_core)
    target_compile_options(neta_history_cli_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    add_test(NAME neta_history_cli_test COMMAND neta_history_cli_test $<TARGET_FILE:neta-agent>)

    foreach(NETA_MS2_TEST IN ITEMS
            connection_direction
            connection_admission_policy
            connection_tracker
            evidence_scheduler
            history_store_ms2
            lifecycle_health
            observation_options
            observation_session
            resource_churn
            storage_maintenance)
        add_executable(neta_${NETA_MS2_TEST}_test tests/${NETA_MS2_TEST}_test.cpp)
        target_link_libraries(neta_${NETA_MS2_TEST}_test PRIVATE neta_core)
        target_compile_options(neta_${NETA_MS2_TEST}_test PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
        add_test(NAME neta_${NETA_MS2_TEST}_test COMMAND neta_${NETA_MS2_TEST}_test)
    endforeach()

    foreach(NETA_MS3_TEST IN ITEMS
            name_resolution
            history_name_resolution
            observation_name_resolution
            tls_session
            history_tls_session
            observation_tls_session)
        add_executable(neta_${NETA_MS3_TEST}_test tests/${NETA_MS3_TEST}_test.cpp)
        target_link_libraries(neta_${NETA_MS3_TEST}_test PRIVATE neta_core)
        target_compile_options(neta_${NETA_MS3_TEST}_test PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
        add_test(NAME neta_${NETA_MS3_TEST}_test COMMAND neta_${NETA_MS3_TEST}_test)
    endforeach()

    add_executable(neta_name_resolution_decoder_test tests/name_resolution_decoder_test.cpp)
    target_link_libraries(neta_name_resolution_decoder_test PRIVATE neta_core)
    target_include_directories(neta_name_resolution_decoder_test PRIVATE src/platform/linux/ebpf)
    target_compile_options(neta_name_resolution_decoder_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    add_test(NAME neta_name_resolution_decoder_test COMMAND neta_name_resolution_decoder_test)

    add_executable(neta_name_resolution_export_replay_test tests/name_resolution_export_replay_test.cpp)
    target_link_libraries(neta_name_resolution_export_replay_test PRIVATE neta_core)
    target_compile_options(neta_name_resolution_export_replay_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    add_test(NAME neta_name_resolution_export_replay_test
             COMMAND neta_name_resolution_export_replay_test $<TARGET_FILE:neta-agent>)

    add_executable(neta_name_resolution_ebpf_integration tests/name_resolution_ebpf_integration.cpp)
    target_link_libraries(neta_name_resolution_ebpf_integration PRIVATE neta_core)
    target_compile_options(neta_name_resolution_ebpf_integration PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    add_test(NAME neta_name_resolution_ebpf_integration COMMAND neta_name_resolution_ebpf_integration)
    set_tests_properties(neta_name_resolution_ebpf_integration PROPERTIES SKIP_RETURN_CODE 77)

    add_executable(neta_tls_session_decoder_test tests/tls_session_decoder_test.cpp)
    target_link_libraries(neta_tls_session_decoder_test PRIVATE neta_core)
    target_include_directories(neta_tls_session_decoder_test PRIVATE src/platform/linux)
    target_compile_options(neta_tls_session_decoder_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    add_test(NAME neta_tls_session_decoder_test COMMAND neta_tls_session_decoder_test)

    add_executable(neta_tls_session_export_replay_test tests/tls_session_export_replay_test.cpp)
    target_link_libraries(neta_tls_session_export_replay_test PRIVATE neta_core)
    target_compile_options(neta_tls_session_export_replay_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    add_test(NAME neta_tls_session_export_replay_test
             COMMAND neta_tls_session_export_replay_test $<TARGET_FILE:neta-agent>)

    if(NETA_TLS_CONTEXT_SHIM_BUILT)
        add_executable(neta_tls_session_shim_integration tests/tls_session_shim_integration.cpp)
        target_link_libraries(neta_tls_session_shim_integration PRIVATE neta_core Threads::Threads)
        target_compile_options(neta_tls_session_shim_integration PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
        add_test(NAME neta_tls_session_shim_integration
            COMMAND ${CMAKE_COMMAND} -E env
                "LD_PRELOAD=$<TARGET_FILE:neta_tls_context>"
                "NETA_TLS_CONTEXT_SOCKET=@neta-agent-tls-ctest"
                $<TARGET_FILE:neta_tls_session_shim_integration>)
    endif()
endif()
