cmake_minimum_required(VERSION 3.14)
project(enp C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# Build options
# ---------------------------------------------------------------------------
option(ENP_WITH_WASM3 "Enable WASM execution via wasm3" ON)

# ---------------------------------------------------------------------------
# Source files
# ---------------------------------------------------------------------------
set(ENP_SOURCES
    main.c
    core/enp_packet.c
    net/enp_server.c
    net/enp_client.c
    wasm/enp_wasm.c
    utils/enp_logger.c
)

add_executable(enp ${ENP_SOURCES})

target_include_directories(enp PRIVATE ${CMAKE_SOURCE_DIR}/include)

# ---------------------------------------------------------------------------
# Platform-specific settings
# ---------------------------------------------------------------------------
if(WIN32)
    target_link_libraries(enp PRIVATE ws2_32)
else()
    target_link_libraries(enp PRIVATE m)
endif()

# ---------------------------------------------------------------------------
# wasm3 integration via FetchContent
# ---------------------------------------------------------------------------
if(ENP_WITH_WASM3)
    include(FetchContent)

    FetchContent_Declare(
        wasm3
        GIT_REPOSITORY https://github.com/wasm3/wasm3.git
        GIT_TAG        v0.5.0
        GIT_SHALLOW    TRUE
    )

    FetchContent_MakeAvailable(wasm3)

    # wasm3 exposes a CMake library target "m3" once fetched
    if(TARGET m3)
        target_compile_definitions(enp PRIVATE ENP_WITH_WASM3)
        target_link_libraries(enp PRIVATE m3)
        target_include_directories(enp PRIVATE
            ${wasm3_SOURCE_DIR}/source
        )
        message(STATUS "ENP: wasm3 found and linked")
    else()
        message(WARNING "ENP: wasm3 FetchContent succeeded but 'm3' target not found – building without WASM support")
    endif()
else()
    message(STATUS "ENP: building without wasm3 (ENP_WITH_WASM3=OFF)")
endif()

# ---------------------------------------------------------------------------
# Compiler warnings
# ---------------------------------------------------------------------------
if(MSVC)
    target_compile_options(enp PRIVATE /W3)
else()
    target_compile_options(enp PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install(TARGETS enp DESTINATION bin)
