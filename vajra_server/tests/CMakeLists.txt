# Unit tests — Catch2 v2 single header vendored at tests/catch2/catch.hpp.
# Header-only units under common/ are tested directly; no DB/Kafka/network needed.

set(VAJRA_TEST_SOURCES
    test_main.cpp
    test_input_validator.cpp
)

# The rate limiter tests target the pinned interface in common/InMemoryRateLimiter.h.
# The header lands from a parallel workstream; guard so the suite builds either way.
if(EXISTS "${CMAKE_SOURCE_DIR}/common/InMemoryRateLimiter.h")
    list(APPEND VAJRA_TEST_SOURCES test_rate_limiter.cpp)
else()
    message(WARNING "common/InMemoryRateLimiter.h not found — skipping rate limiter tests (tests/test_rate_limiter.cpp expresses the pinned contract)")
endif()

add_executable(vajra_tests ${VAJRA_TEST_SOURCES})

target_include_directories(vajra_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
)

target_compile_options(vajra_tests PRIVATE -Wall -Wextra)

find_package(Threads REQUIRED)
target_link_libraries(vajra_tests PRIVATE Threads::Threads)

add_test(NAME vajra_unit_tests COMMAND vajra_tests)
