cmake_minimum_required(VERSION 3.10)
project(Aegis VERSION 0.1.0 LANGUAGES C)

# Find dependencies
find_package(OpenSSL REQUIRED)
find_package(OQS REQUIRED)

# Set compilation flags
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

# Aegis library
add_library(aegis SHARED
    src/aegis_core.c
)

target_include_directories(aegis PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${OQS_INCLUDE_DIRS}
)

target_link_libraries(aegis PUBLIC
    ${OPENSSL_LIBRARIES}
    OQS::oqs
)

# Installation
install(TARGETS aegis
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES include/aegis_core.h
    DESTINATION include
)
