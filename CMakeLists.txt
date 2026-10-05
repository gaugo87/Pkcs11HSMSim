cmake_minimum_required(VERSION 3.24)
project(hsm-simulator VERSION 0.6.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS OFF)

find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)

set(HSM_SOURCES
    src/core/runtime.cpp
    src/core/utilities.cpp
    src/crypto/derivation.cpp
    src/crypto/key_generation.cpp
    src/crypto/mechanisms.cpp
    src/crypto/signature.cpp
    src/crypto/wrapping.cpp
    src/objects/attributes.cpp
    src/objects/objects.cpp
    src/objects/policy.cpp
    src/objects/template.cpp
    src/pkcs11/entry_points.cpp
    src/pkcs11/interfaces.cpp
    src/pkcs11/sessions.cpp
    src/pkcs11/unsupported.cpp
    src/pkcs11/token.cpp
    src/storage/key_store.cpp
    src/storage/metadata.cpp
)

add_library(hsm-simulator SHARED ${HSM_SOURCES})
target_include_directories(hsm-simulator PUBLIC include PRIVATE src)
target_link_libraries(hsm-simulator PRIVATE OpenSSL::Crypto)
target_compile_definitions(hsm-simulator PRIVATE HSM_SIM_BUILD)
set_target_properties(hsm-simulator PROPERTIES
    OUTPUT_NAME "hsm-simulator"
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

if(WIN32)
    # Keep PKCS#11 export names undecorated on both Win32 and x64.
    target_sources(hsm-simulator PRIVATE src/hsm-simulator.def)
endif()
if(MSVC)
    target_compile_options(hsm-simulator PRIVATE /W4 /permissive- /EHsc /utf-8)
endif()

include(CTest)
if(BUILD_TESTING)
    # Each integration test receives an isolated token directory from run.cmake.
    function(hsm_add_test name)
        add_executable(hsm-${name} tests/${name}.cpp)
        target_link_libraries(hsm-${name} PRIVATE hsm-simulator ${ARGN})
        add_test(NAME ${name} COMMAND ${CMAKE_COMMAND}
            -DTEST_PROGRAM=$<TARGET_FILE:hsm-${name}>
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/run.cmake
        )
    endfunction()

    hsm_add_test(policy)
    hsm_add_test(derive)
    hsm_add_test(mldsa OpenSSL::Crypto)

    # Deliberately do not link the loader test to the simulator import library.
    add_executable(hsm-loader tests/loader.cpp)
    target_include_directories(hsm-loader PRIVATE include)
    target_link_libraries(hsm-loader PRIVATE ${CMAKE_DL_LIBS})
    add_dependencies(hsm-loader hsm-simulator)
    add_test(NAME loader COMMAND ${CMAKE_COMMAND}
        -DTEST_PROGRAM=$<TARGET_FILE:hsm-loader>
        -DTEST_ARGUMENT=$<TARGET_FILE:hsm-simulator>
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/run.cmake
    )

    hsm_add_test(smoke ${CMAKE_DL_LIBS})
    hsm_add_test(persistence)
    hsm_add_test(pss OpenSSL::Crypto)
    hsm_add_test(regression OpenSSL::Crypto)
endif()

# Formatting is opt-in and never touches the third-party OASIS headers.
find_program(CLANG_FORMAT_EXECUTABLE NAMES clang-format clang-format-18)
if(CLANG_FORMAT_EXECUTABLE)
    file(GLOB_RECURSE HSM_HEADERS CONFIGURE_DEPENDS "src/*.hpp")
    file(GLOB HSM_TEST_SOURCES CONFIGURE_DEPENDS "tests/*.cpp")
    set(HSM_FORMAT_FILES ${HSM_SOURCES} ${HSM_HEADERS} ${HSM_TEST_SOURCES})
    add_custom_target(format
        COMMAND ${CLANG_FORMAT_EXECUTABLE} -i ${HSM_FORMAT_FILES}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        VERBATIM
    )
    add_custom_target(check-format
        COMMAND ${CLANG_FORMAT_EXECUTABLE} --dry-run --Werror ${HSM_FORMAT_FILES}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        VERBATIM
    )
endif()
