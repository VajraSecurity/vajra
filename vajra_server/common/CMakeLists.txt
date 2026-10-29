cmake_minimum_required(VERSION 3.16)
project(vajraServerSdk)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Only the sources actually used by vajra_server, vajra_engine_v2 and rule_builder.
# EdrDataTypes.h is listed because rule_builder.cpp includes it directly.
add_library(vajraServerSdk SHARED ConfigurationParser.cpp ConnectionPool.cpp EdrDataTypes.h hostinfo.cpp hostinfo.h ThreadPool.cpp ThreadPool.h)
target_link_libraries(vajraServerSdk vendored_pqxx)
target_link_libraries(vajraServerSdk -lboost_log_setup)
target_link_libraries(vajraServerSdk -lboost_log)
target_link_libraries(vajraServerSdk -lboost_thread)
target_link_libraries(vajraServerSdk ${VAJRA_BOOST_SYSTEM_LIBS})
