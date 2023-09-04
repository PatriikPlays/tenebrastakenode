cmake_minimum_required(VERSION 3.27)
project(tenebrastakenode)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
    elseif(MSVC)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /O2")
    endif()
endif()

find_package(OpenSSL REQUIRED)

include_directories(/usr/include/curl/)

set(USE_TLS ON)
add_subdirectory(${CMAKE_SOURCE_DIR}/IXWebSocket)

add_executable(tenebrastakenode main.cpp)
target_link_libraries(tenebrastakenode OpenSSL::SSL)
target_link_libraries(tenebrastakenode /usr/lib/libz.so.1)
target_link_libraries(tenebrastakenode ixwebsocket)
target_link_libraries(tenebrastakenode curl)
target_include_directories(tenebrastakenode PUBLIC /usr/include/nlohmann)