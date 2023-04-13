# ================================================================================================
#  DS3OS
#  Copyright (C) 2021 Tim Leonard
# ================================================================================================

project(Injector C CXX)

enable_language(ASM_MASM)

SET(SOURCES
    Entry.cpp

    Config/BuildConfig.h
    Config/RuntimeConfig.h
    Config/RuntimeConfig.cpp
    
    Injector/Injector.h
    Injector/Injector.cpp

    Hooks/Hook.h
    Hooks/Hook.cpp
    Hooks/ReplaceServerAddressHook.h
    Hooks/ReplaceServerAddressHook.cpp
    Hooks/ChangeSaveGameFilenameHook.h
    Hooks/ChangeSaveGameFilenameHook.cpp

    Hooks/Advanced/AdvancedHook.h
    Hooks/Advanced/AdvancedHook.cpp
    Hooks/Advanced/LockOnAdjustHook.h
    Hooks/Advanced/LockOnAdjustHook.cpp


    ASM/ASMGlobals.h
    ASM/ASMGlobals.cpp
    ASM/LockOnAdjustHookWrapper.asm
)
 
add_library(${PROJECT_NAME} SHARED ${SOURCES} ${PLATFORM_SOURCES})

target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/../")

target_compile_definitions(${PROJECT_NAME} PRIVATE -D_CRT_SECURE_NO_WARNINGS -D_WINSOCK_DEPRECATED_NO_WARNINGS -D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)

util_setup_folder_structure(${PROJECT_NAME} SOURCES "DS3OS")

set_target_properties(Injector PROPERTIES
    VS_DEBUGGER_COMMAND "$(TargetDir)/Loader.exe"
)

target_link_libraries(
    ${PROJECT_NAME}
    Shared
    detours
)