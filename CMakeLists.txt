cmake_minimum_required(VERSION 3.16)
project(VPack VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(VPACK_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
file(MAKE_DIRECTORY "${VPACK_BIN_DIR}")

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_compile_options(/W4 /permissive- /EHsc /Gy /Gw /MT)
    add_link_options(/OPT:REF /OPT:ICF)
else()
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -ffunction-sections -fdata-sections
        -fvisibility=hidden -fvisibility-inlines-hidden
        -fno-rtti -fno-ident -g0
    )
    add_link_options(
        -static
        -static-libgcc
        -static-libstdc++
        -Wl,--gc-sections
        -Wl,--strip-all
        -s
    )
endif()

set(VPACK_SYS_LIBS Advapi32 User32 Psapi Kernel32 Ntdll)

# 1. Core VPack Static Library (SDK + Runtime + VM + PE Parser)
add_library(vpack STATIC
    src/crypto.cpp
    src/anti_debug.cpp
    src/anti_dump.cpp
    src/vm.cpp
    src/pe_parser.cpp
    src/vpack_sdk.cpp
)
target_include_directories(vpack PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(vpack PUBLIC ${VPACK_SYS_LIBS})

# 2. VPack CLI Tool (Inspector & PE64 Packer)
add_executable(vpack_cli
    tools/vpack_cli.cpp
)
target_link_libraries(vpack_cli PRIVATE vpack ${VPACK_SYS_LIBS})

# 3. Protected Demo Application (Persistent Memory Guard & VM)
add_executable(demo_app
    examples/demo_app.cpp
)
target_link_libraries(demo_app PRIVATE vpack ${VPACK_SYS_LIBS})
add_custom_command(TARGET demo_app POST_BUILD
    COMMAND $<TARGET_FILE:vpack_cli> pack $<TARGET_FILE:demo_app> "${VPACK_BIN_DIR}/demo_app_standalone.exe"
    COMMENT "Auto-packing demo_app -> Bin/demo_app_standalone.exe"
)

# 4. Protected Key-Gated Loader / CrackMe Challenge
add_executable(crackme_loader
    examples/crackme_loader.cpp
)
target_link_libraries(crackme_loader PRIVATE vpack ${VPACK_SYS_LIBS})
add_custom_command(TARGET crackme_loader POST_BUILD
    COMMAND $<TARGET_FILE:vpack_cli> pack $<TARGET_FILE:crackme_loader> "${VPACK_BIN_DIR}/crackme_standalone.exe"
    COMMENT "Auto-packing crackme_loader -> Bin/crackme_standalone.exe"
)

# 5. Optional: In-Process Memory Dumper DLL & Injector (only built if tests/ exists locally)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/dumper_dll.cpp")
    add_library(dumper_dll SHARED
        tests/dumper_dll.cpp
    )
    set_target_properties(dumper_dll PROPERTIES PREFIX "")
    target_link_libraries(dumper_dll PRIVATE ${VPACK_SYS_LIBS})
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/dll_injector.cpp")
    add_executable(dll_injector
        tests/dll_injector.cpp
    )
    target_link_libraries(dll_injector PRIVATE vpack ${VPACK_SYS_LIBS})
endif()

# 6. Optional: ACE Out-of-Process Emulator (only built if emu/ exists locally)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/emu/src/main.cpp")
    add_executable(emu
        emu/src/core/logger.cpp
        emu/src/ipc/global_sync.cpp
        emu/src/ipc/smem_ring.cpp
        emu/src/ipc/pipe_server.cpp
        emu/src/ipc/sguard_server.cpp
        emu/src/memory/process_scanner.cpp
        emu/src/memory/state_orchestrator.cpp
        emu/src/orchestrator/engine.cpp
        emu/src/main.cpp
    )
    target_include_directories(emu PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/emu/include
        ${CMAKE_CURRENT_SOURCE_DIR}/emu/src
    )
    target_compile_features(emu PRIVATE cxx_std_20)
    target_compile_definitions(emu PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        UNICODE
        _UNICODE
    )
    target_link_libraries(emu PRIVATE vpack ${VPACK_SYS_LIBS})
    if(MINGW)
        target_link_options(emu PRIVATE -municode -static -static-libgcc -static-libstdc++)
    endif()
    add_custom_command(TARGET emu POST_BUILD
        COMMAND $<TARGET_FILE:vpack_cli> pack $<TARGET_FILE:emu> "${VPACK_BIN_DIR}/emu_standalone.exe"
        COMMENT "Auto-packing emu -> Bin/emu_standalone.exe"
    )
endif()
