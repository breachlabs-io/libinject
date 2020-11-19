cmake_minimum_required(VERSION 3.16.3)

project(inject LANGUAGES C VERSION 0.0.1)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static-pie")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")

set(LPM_LIB_DIR "${CMAKE_SOURCE_DIR}/libs")
set(LPM_LIBREFLECT_DIR "${LPM_LIB_DIR}/libreflect")

file(GLOB SOURCES src/*.c)
add_executable(inject ${SOURCES})
target_include_directories(inject PRIVATE include/ ${LPM_LIBREFLECT_DIR}/include/)
target_link_libraries(inject ${LPM_LIBREFLECT_DIR}/libreflect.a)
