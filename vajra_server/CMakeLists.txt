cmake_minimum_required(VERSION 3.16)
project(vajra)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Targets: vajra_server (ingest), rule_builder and the test suite.
# engine_v2 is a separate standalone project (see engine_v2/CMakeLists.txt).

# Vendored C++20-built static libpqxx (ABI match).
# The distro libpqxx-7.8.so was compiled under C++17 (no __cpp_lib_source_location),
# so linking it into our C++20 build fails with undefined references on pqxx
# exception constructors (e.g. pqxx::range_error(string, source_location)). We
# link the vendored static build (same 7.8.1, compiled -DCMAKE_CXX_STANDARD=20)
# instead. Rebuild with scripts/bootstrap_deps_pqxx.sh if 3rdparty/local is absent
# (it will also need 3rdparty/libpqxx-7.8.1 source, which this repository does
# not vendor -- see scripts/bootstrap_deps_pqxx.sh / CI for how it's fetched).
set(VAJRA_PQXX_PREFIX ${CMAKE_SOURCE_DIR}/3rdparty/local)
if(NOT EXISTS ${VAJRA_PQXX_PREFIX}/lib/libpqxx.a)
    message(FATAL_ERROR
        "Vendored libpqxx not found at ${VAJRA_PQXX_PREFIX}/lib/libpqxx.a. "
        "Fetch 3rdparty/libpqxx-7.8.1 (see .github/workflows/ci.yml for the exact "
        "source URL) then run scripts/bootstrap_deps_pqxx.sh to build it.")
endif()
add_library(vendored_pqxx STATIC IMPORTED GLOBAL)
set_target_properties(vendored_pqxx PROPERTIES
    IMPORTED_LOCATION ${VAJRA_PQXX_PREFIX}/lib/libpqxx.a
    INTERFACE_INCLUDE_DIRECTORIES ${VAJRA_PQXX_PREFIX}/include
    INTERFACE_LINK_LIBRARIES pq)

# Default to Release when no build type is specified (multi-config generators ignore this).
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Copy config.json to build directory during configuration.
# config.json holds live credentials and is not tracked; fall back to
# config.template.json so fresh checkouts (and CI) can still configure.
if(EXISTS ${CMAKE_SOURCE_DIR}/config.json)
    configure_file(
        ${CMAKE_SOURCE_DIR}/config.json
        ${CMAKE_BINARY_DIR}/config.json
        COPYONLY
    )
elseif(EXISTS ${CMAKE_SOURCE_DIR}/config.template.json)
    configure_file(
        ${CMAKE_SOURCE_DIR}/config.template.json
        ${CMAKE_BINARY_DIR}/config.json
        COPYONLY
    )
else()
    message(WARNING "No config.json or config.template.json found — build directory will have no config.json")
endif()

# Boost >= 1.69 made boost_system header-only (boost::system::error_code no
# longer needs a compiled definition); many distro packagers, especially on
# newer releases, stopped shipping a linkable libboost_system stub at all
# since nothing actually needs it anymore, even though libboost-*-dev still
# installs fine. Hardcoding -lboost_system unconditionally then fails the
# link step on those distros. Link it only if it's actually present; skip it
# otherwise -- Boost.Asio/Beast (what this project actually uses) work fine
# either way. Set once here (before add_subdirectory) so common/CMakeLists.txt
# picks it up via normal parent-scope variable inheritance.
find_library(VAJRA_BOOST_SYSTEM_LIB boost_system)
if(VAJRA_BOOST_SYSTEM_LIB)
    set(VAJRA_BOOST_SYSTEM_LIBS boost_system)
else()
    set(VAJRA_BOOST_SYSTEM_LIBS "")
    message(STATUS "libboost_system not found -- skipping (header-only since Boost 1.69, not required)")
endif()

add_subdirectory(${PROJECT_SOURCE_DIR}/common)

add_executable(rule_builder
    rule_builder/main.cpp
    rule_builder/rule_builder.cpp
    rule_builder/rule_builder.h
)
target_compile_options(rule_builder PRIVATE -Wall -Wextra)
target_link_libraries(rule_builder -ldl)
target_link_libraries(rule_builder vajraServerSdk)
target_link_libraries(rule_builder -lpthread)
target_link_libraries(rule_builder vendored_pqxx)

add_executable(vajra_server
    server/fleet_main.cpp
    server/WebServer.cpp
    server/request_handler.cpp
    server/request_handler.h
    server/RequestRouter.cpp
    server/RequestRouter.h
    server/http_common.cpp
    server/http_common.h
    server/api/health.cpp
    server/KafkaProducerManager.h
    server/KafkaProducerManager.cpp
)
target_compile_options(vajra_server PRIVATE -Wall -Wextra)
target_link_libraries(vajra_server -lboost_log_setup)
target_link_libraries(vajra_server -lboost_log)
target_link_libraries(vajra_server -lboost_thread)
target_link_libraries(vajra_server ${VAJRA_BOOST_SYSTEM_LIBS})
target_link_libraries(vajra_server -lssl)
target_link_libraries(vajra_server -lcrypto)
target_link_libraries(vajra_server -lpthread)
target_link_libraries(vajra_server -lrdkafka++)
target_link_libraries(vajra_server -lrdkafka)
target_link_libraries(vajra_server vajraServerSdk)
target_link_libraries(vajra_server vendored_pqxx)

enable_testing()
add_subdirectory(${PROJECT_SOURCE_DIR}/tests)
