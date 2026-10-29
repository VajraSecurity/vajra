# Unit tests for engine_v2 -- same Catch2-v2-single-header pattern as the
# repo root's tests/ (vendored header reused directly from there, not
# duplicated: see the include directory below).

set(VAJRA_ENGINE_V2_TEST_SOURCES
    test_main.cpp
    test_correlation_engine.cpp
    test_decoder_hardening.cpp
    test_ruleset_loader_hardening.cpp
    test_expressiveness_operators.cpp
    test_metrics_server.cpp
    test_list_store_icase.cpp
    test_regex_search_bounded.cpp
)

add_executable(vajra_engine_v2_tests ${VAJRA_ENGINE_V2_TEST_SOURCES})

target_include_directories(vajra_engine_v2_tests PRIVATE
    ${VAJRA_REPO_ROOT}/tests
)

target_compile_options(vajra_engine_v2_tests PRIVATE -Wall -Wextra)

find_package(Threads REQUIRED)
target_link_libraries(vajra_engine_v2_tests PRIVATE Threads::Threads)
target_link_libraries(vajra_engine_v2_tests PRIVATE vajra_engine_v2_lib)

add_test(NAME vajra_engine_v2_unit_tests COMMAND vajra_engine_v2_tests)
