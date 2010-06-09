
cmake_minimum_required(VERSION 2.6)

project(sofsip_ring)

find_package(PkgConfig)

pkg_check_modules(SOFIA_SIP REQUIRED sofia-sip-ua)

include_directories(${SOFIA_SIP_INCLUDE_DIRS})

add_executable(sofsip_ring main.cpp)
target_link_libraries(sofsip_ring ${SOFIA_SIP_LIBRARIES})
