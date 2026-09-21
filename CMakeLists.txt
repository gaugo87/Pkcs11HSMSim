cmake_minimum_required(VERSION 3.24)
project(hsm-simulator VERSION 0.6.0 LANGUAGES CXX)
if(WIN32 AND NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "The Windows simulator requires an x64 build.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS OFF)

find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)

add_library(hsm-simulator SHARED
    src/module.cpp
)
target_include_directories(hsm-simulator PUBLIC include)
target_link_libraries(hsm-simulator PRIVATE OpenSSL::Crypto)
target_compile_definitions(hsm-simulator PRIVATE HSM_SIM_BUILD)
if(MSVC)
  target_compile_options(hsm-simulator PRIVATE /W4 /permissive- /EHsc /utf-8)
  set_target_properties(hsm-simulator PROPERTIES OUTPUT_NAME "hsm-simulator")
endif()

add_executable(hsm-smoke tests/smoke.cpp)
target_include_directories(hsm-smoke PRIVATE include)
if(WIN32)
  target_link_libraries(hsm-smoke PRIVATE hsm-simulator)
else()
  target_link_libraries(hsm-smoke PRIVATE hsm-simulator dl)
endif()

enable_testing()
add_executable(hsm-mldsa tests/mldsa.cpp)
target_include_directories(hsm-mldsa PRIVATE include)
target_link_libraries(hsm-mldsa PRIVATE hsm-simulator OpenSSL::Crypto)
add_test(NAME mldsa COMMAND ${CMAKE_COMMAND}
 -DTEST_PROGRAM=$<TARGET_FILE:hsm-mldsa> -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/run.cmake)
add_executable(hsm-loader tests/loader.cpp)
target_include_directories(hsm-loader PRIVATE include)
target_link_libraries(hsm-loader PRIVATE ${CMAKE_DL_LIBS})
add_dependencies(hsm-loader hsm-simulator)
add_test(NAME loader COMMAND ${CMAKE_COMMAND}
 -DTEST_PROGRAM=$<TARGET_FILE:hsm-loader>
 -DTEST_ARGUMENT=$<TARGET_FILE:hsm-simulator>
 -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/run.cmake)
add_test(NAME smoke COMMAND ${CMAKE_COMMAND}
 -DTEST_PROGRAM=$<TARGET_FILE:hsm-smoke> -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/run.cmake)
add_executable(hsm-regression tests/regression.cpp)
target_include_directories(hsm-regression PRIVATE include)
target_link_libraries(hsm-regression PRIVATE hsm-simulator OpenSSL::Crypto)
add_executable(hsm-pss tests/pss.cpp)
add_executable(hsm-persistence tests/persistence.cpp)
target_include_directories(hsm-persistence PRIVATE include)
target_link_libraries(hsm-persistence PRIVATE hsm-simulator)
add_test(NAME persistence COMMAND ${CMAKE_COMMAND}
 -DTEST_PROGRAM=$<TARGET_FILE:hsm-persistence> -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/run.cmake)
target_include_directories(hsm-pss PRIVATE include)
target_link_libraries(hsm-pss PRIVATE hsm-simulator OpenSSL::Crypto)
add_test(NAME pss COMMAND ${CMAKE_COMMAND}
 -DTEST_PROGRAM=$<TARGET_FILE:hsm-pss> -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/run.cmake)
add_test(NAME regression COMMAND ${CMAKE_COMMAND}
 -DTEST_PROGRAM=$<TARGET_FILE:hsm-regression> -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/run.cmake)
