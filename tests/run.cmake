# Unique, disposable test token. Never point integration tests at the user's token.
string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef suffix)
set(token_dir "${CMAKE_CURRENT_BINARY_DIR}/test-tokens/${suffix}")
file(MAKE_DIRECTORY "${token_dir}")
execute_process(
 COMMAND "${CMAKE_COMMAND}" -E env
 "HSM_SIM_DATA_DIR=${token_dir}" "HSM_SIM_P12_PASSWORD=" "HSM_SIM_PIN="
 "${TEST_PROGRAM}" ${TEST_ARGUMENT}
 RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
 message(FATAL_ERROR "Test failed: ${result}. Token retained at ${token_dir}")
endif()
