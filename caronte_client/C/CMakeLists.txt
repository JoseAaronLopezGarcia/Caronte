##############################################
#   CMake
##############################################
project(caronte_client C)
cmake_minimum_required(VERSION 2.8)
include(CheckIncludeFiles)
include(CheckSymbolExists)

# set(CMAKE_INSTALL_PREFIX /yuneta/development/output)
#set(CMAKE_INSTALL_PREFIX ./)

set(INC_DEST_DIR ${CMAKE_INSTALL_PREFIX}/include)
set(LIB_DEST_DIR ${CMAKE_INSTALL_PREFIX}/lib)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

if(CMAKE_BUILD_TYPE MATCHES Debug)
  add_definitions(-DDEBUG)
  option(SHOWNOTES "Show preprocessor notes" OFF)

  if(CMAKE_COMPILER_IS_GNUCC)
    # GCC specific debug options
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g3 -ggdb3 -gdwarf-2")
    set(AVOID_VERSION -avoid-version)
  endif(CMAKE_COMPILER_IS_GNUCC)
endif(CMAKE_BUILD_TYPE MATCHES Debug)

# add_definitions(-D_GNU_SOURCE)
# add_definitions(-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64)

# include_directories(BEFORE /yuneta/development/output/include)

##############################################
#   Source
##############################################

set (SRCS
    utils.c
    base64.c
    cJSON.c
    hashmap.c
    http_client.c
    caronte_security.c
    caronte_client.c
)


set (HDRS
    caronte_client.h
    caronte_security.h
    utils.h
)


##############################################
#   Lib
##############################################
add_library(caronte ${SRCS} ${HDRS})

##############################################
#   System install
##############################################
install(FILES ${HDRS} DESTINATION ${INC_DEST_DIR})

install(
    TARGETS caronte
    PERMISSIONS
    OWNER_READ OWNER_WRITE
    GROUP_READ GROUP_WRITE
    WORLD_READ
    DESTINATION ${LIB_DEST_DIR}
)

##############################################
#   sub-projects
##############################################
