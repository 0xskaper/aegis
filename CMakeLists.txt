cmake_minimum_required(VERSION 3.10)
project(Aegis VERSION 0.1.0 LANGUAGES C)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Try to find OQS package - with robust fallback mechanisms
find_package(OQS QUIET)

# If not found, try alternative methods
if(NOT OQS_FOUND)
  # Try to find using pkg-config
  find_package(PkgConfig QUIET)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(OQS QUIET liboqs)
  endif()
  
  # If still not found, use manually specified location
  if(NOT OQS_FOUND)
    message(STATUS "OQS not found through standard means, using fallback paths")
    
    # Try to find the header files
    find_path(OQS_INCLUDE_DIR
      NAMES oqs/oqs.h
      PATHS /usr/local/include /usr/include
      DOC "OQS include directory"
    )
    
    # Try to find the library
    find_library(OQS_LIBRARY
      NAMES oqs liboqs
      PATHS /usr/local/lib /usr/lib
      DOC "OQS library"
    )
    
    # Set the variables expected by the rest of the script
    if(OQS_INCLUDE_DIR AND OQS_LIBRARY)
      set(OQS_INCLUDE_DIRS ${OQS_INCLUDE_DIR})
      set(OQS_LIBRARIES ${OQS_LIBRARY})
      set(OQS_FOUND TRUE)
    endif()
  endif()
endif()

# Verify OQS was found
if(NOT OQS_FOUND)
  message(FATAL_ERROR "Could not find liboqs. Please install it or specify its location with -DOQS_DIR=/path/to/liboqs or -DOQS_INCLUDE_DIR=/path/to/include -DOQS_LIBRARY=/path/to/lib/liboqs.so")
else()
  message(STATUS "Found OQS: ${OQS_LIBRARIES}")
endif()

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
    ${OQS_LIBRARIES}
)

# Installation
install(TARGETS aegis
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES include/aegis_core.h
    DESTINATION include
)
