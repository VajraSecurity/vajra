# Standalone build for engine_v2, the detection/correlation engine.
# Deliberately a SEPARATE CMake project from the repo root's CMakeLists.txt:
# configure/build this directory directly, e.g.
#   cmake -S engine_v2 -B engine_v2/build -DCMAKE_BUILD_TYPE=Release
#   cmake --build engine_v2/build -j
#
# Uses the same vendored-pqxx ABI-match approach and the same shared
# common/ sources as the root CMakeLists.txt, with -Wall -Wextra -Werror.
# Differences from the root build are called out inline below.

cmake_minimum_required(VERSION 3.16)
project(vajra_engine_v2 CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Repo root, one level up from this file.
set(VAJRA_REPO_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Vendored C++20-built static libpqxx (ABI match) -- identical rationale and
# path to the root CMakeLists.txt's own vendored_pqxx target (see its
# comment): the distro libpqxx is C++17-compiled and fails to link into a
# C++20 build. Re-declared here (not shared with the root build) because
# this is a genuinely separate CMake project/configure; both point at the
# SAME on-disk artifact under 3rdparty/local, built once by
# scripts/bootstrap_deps_pqxx.sh regardless of which project links it.
set(VAJRA_PQXX_PREFIX ${VAJRA_REPO_ROOT}/3rdparty/local)
if(NOT EXISTS ${VAJRA_PQXX_PREFIX}/lib/libpqxx.a)
    message(FATAL_ERROR
        "Vendored libpqxx not found at ${VAJRA_PQXX_PREFIX}/lib/libpqxx.a. "
        "Run scripts/bootstrap_deps_pqxx.sh (from the repo root) to build it.")
endif()
add_library(vendored_pqxx STATIC IMPORTED GLOBAL)
set_target_properties(vendored_pqxx PROPERTIES
    IMPORTED_LOCATION ${VAJRA_PQXX_PREFIX}/lib/libpqxx.a
    INTERFACE_INCLUDE_DIRECTORIES ${VAJRA_PQXX_PREFIX}/include
    INTERFACE_LINK_LIBRARIES pq)

# Copy config.json (or config.template.json) into the build dir so
# vajra_engine_v2/vajra_engine_v2_eval can run with the default "config.json"
# relative path, same convenience the root build provides.
if(EXISTS ${VAJRA_REPO_ROOT}/config.json)
    configure_file(${VAJRA_REPO_ROOT}/config.json ${CMAKE_BINARY_DIR}/config.json COPYONLY)
elseif(EXISTS ${VAJRA_REPO_ROOT}/config.template.json)
    configure_file(${VAJRA_REPO_ROOT}/config.template.json ${CMAKE_BINARY_DIR}/config.json COPYONLY)
else()
    message(WARNING "No config.json or config.template.json found — build directory will have no config.json")
endif()

# vajraServerSdk (ConnectionPool/ConfigurationParser/logger et al.) -- built
# from the SAME common/ sources the root project uses, into a private binary
# dir under this build tree so the two CMake projects never collide on
# build artifacts.
add_subdirectory(${VAJRA_REPO_ROOT}/common ${CMAKE_BINARY_DIR}/common)

find_package(CURL REQUIRED)

# engine_v2's own library: Vega's Decoder/RuleEngine/RulesetLoader/
# BuiltinRules/KafkaConsumer/Metrics sources plus Nyx's AlertWriter/
# ThreatIntelFeed/CorrelationEngine/IncidentWriter -- one target, since
# main.cpp and the eval/test binaries need all of it linked together
# in one library.
add_library(vajra_engine_v2_lib STATIC
    src/Decoder.cpp
    src/RuleEngine.cpp
    src/AlertWriter.cpp
    src/BuiltinRules.cpp
    src/RulesetLoader.cpp
    src/KafkaConsumer.cpp
    src/ThreatIntelFeed.cpp
    src/Metrics.cpp
    src/CorrelationEngine.cpp
    src/IncidentWriter.cpp
)
target_include_directories(vajra_engine_v2_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(vajra_engine_v2_lib PRIVATE -Wall -Wextra -Werror)
target_link_libraries(vajra_engine_v2_lib vajraServerSdk)
target_link_libraries(vajra_engine_v2_lib vendored_pqxx)
target_link_libraries(vajra_engine_v2_lib -lrdkafka++)
target_link_libraries(vajra_engine_v2_lib -lrdkafka)
target_link_libraries(vajra_engine_v2_lib CURL::libcurl)

add_executable(vajra_engine_v2
    src/main.cpp
    ${VAJRA_REPO_ROOT}/server/KafkaProducerManager.h
    ${VAJRA_REPO_ROOT}/server/KafkaProducerManager.cpp
)
target_compile_options(vajra_engine_v2 PRIVATE -Wall -Wextra -Werror)
target_link_libraries(vajra_engine_v2 vajra_engine_v2_lib)
target_link_libraries(vajra_engine_v2 vajraServerSdk)
target_link_libraries(vajra_engine_v2 vendored_pqxx)
target_link_libraries(vajra_engine_v2 -lboost_log_setup)
target_link_libraries(vajra_engine_v2 -lboost_log)
target_link_libraries(vajra_engine_v2 -lboost_thread)
# boost_system is header-only since Boost 1.69 and some distros no longer ship the
# library, so link it only when it exists (same approach as the root CMakeLists.txt).
find_library(VAJRA_BOOST_SYSTEM_LIB boost_system)
if(VAJRA_BOOST_SYSTEM_LIB)
    target_link_libraries(vajra_engine_v2 boost_system)
endif()
target_link_libraries(vajra_engine_v2 -lrdkafka++)
target_link_libraries(vajra_engine_v2 -lrdkafka)
target_link_libraries(vajra_engine_v2 -lpthread)

# Offline eval tool -- unchanged pipeline (Decoder/RuleEngine only, no DB/
# Kafka/correlation); see tools/eval_main.cpp.
add_executable(vajra_engine_v2_eval tools/eval_main.cpp)
target_compile_options(vajra_engine_v2_eval PRIVATE -Wall -Wextra -Werror)
target_link_libraries(vajra_engine_v2_eval vajra_engine_v2_lib)

# Offline correlation-ruleset validator -- rule_engine_ui (Console-BE)'s
# validation entry point for {"correlations": [...]} documents, since
# vajra_engine_v2_eval above only loads detection "rules" (see
# tools/correlation_validate.cpp's top comment). Additive-only new file/
# target, mirrors vajra_engine_v2_eval's build wiring.
add_executable(vajra_engine_v2_correlation_validate tools/correlation_validate.cpp)
target_compile_options(vajra_engine_v2_correlation_validate PRIVATE -Wall -Wextra -Werror)
target_link_libraries(vajra_engine_v2_correlation_validate vajra_engine_v2_lib)

# STIX Feeds preview tool -- rule_engine_ui (Console-BE)'s
# POST /api/threat-intel-feeds/{name}/preview entry point (API_CONTRACT_V2.md
# section 3). Calls the real parse_abuseipdb_blacklist()/parse_stix_indicators()
# free functions from ThreatIntelFeed.h/.cpp directly (no reimplementation).
# Additive-only new file/target, mirrors vajra_engine_v2_eval's build wiring;
# needs CURL directly (its own small fetch(), see tools/feed_preview.cpp's
# top comment on why it doesn't reuse ThreatIntelFeed.cpp's private one).
add_executable(vajra_engine_v2_feed_preview tools/feed_preview.cpp)
target_compile_options(vajra_engine_v2_feed_preview PRIVATE -Wall -Wextra -Werror)
target_link_libraries(vajra_engine_v2_feed_preview vajra_engine_v2_lib)
target_link_libraries(vajra_engine_v2_feed_preview CURL::libcurl)

# Live-DB regression tool for the AlertWriter dedup-identity fix (Sage's
# round-2 review, Finding 3) -- deliberately NOT part of the Catch2 suite
# (which never opens a DB connection, see tests/CMakeLists.txt); run
# manually against a disposable test database. See tools/
# verify_alertwriter_dedup.cpp's top comment for usage/safety notes.
add_executable(vajra_engine_v2_verify_alertwriter_dedup tools/verify_alertwriter_dedup.cpp)
target_compile_options(vajra_engine_v2_verify_alertwriter_dedup PRIVATE -Wall -Wextra -Werror)
target_link_libraries(vajra_engine_v2_verify_alertwriter_dedup vajra_engine_v2_lib)
target_link_libraries(vajra_engine_v2_verify_alertwriter_dedup vajraServerSdk)
target_link_libraries(vajra_engine_v2_verify_alertwriter_dedup vendored_pqxx)

# Offline, ORDERED multi-event correlation simulator -- rule_engine_ui
# (Console-Sim)'s tool for proving a {"correlations": [...]} rule actually
# fires an Incident given a real event SEQUENCE, since neither
# vajra_engine_v2_eval (no CorrelationEngine at all) nor
# vajra_engine_v2_correlation_validate (load-only, never calls ingest())
# exercise correlation logic. Additive-only new file/target, mirrors
# vajra_engine_v2_eval's/vajra_engine_v2_correlation_validate's build wiring.
add_executable(vajra_engine_v2_correlation_simulate tools/correlation_simulate.cpp)
target_compile_options(vajra_engine_v2_correlation_simulate PRIVATE -Wall -Wextra -Werror)
target_link_libraries(vajra_engine_v2_correlation_simulate vajra_engine_v2_lib)

enable_testing()
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tests)
