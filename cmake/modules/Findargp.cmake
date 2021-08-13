# - Find argp
# Figure out if argp is in glibc or if it argp-standalone
#
#  ARGP_LIBRARY     - Library to use argp
#  ARGP_FOUND       - True if found.

message(STATUS "Checking availability of argp library")

INCLUDE(CheckLibraryExists)

if (ARGP_LIBRARY)
	# Already in cache, be silent
	set(ARGP_FIND_QUIETLY TRUE)
endif (ARGP_LIBRARY)

find_library(ARGP_LIBRARY
	NAMES argp
	PATHS /usr/lib /usr/local/lib /usr/lib64 /usr/local/lib64 ~/usr/local/lib ~/usr/local/lib64
)

if (ARGP_LIBRARY)
	set(ARGP_FOUND TRUE)
	set(ARGP_LIBRARY ${ARGP_LIBRARY})
	set(CMAKE_REQUIRED_LIBRARIES ${ARGP_LIBRARY})
else (ARGP_LIBRARY)
	set(ARGP_LIBRARY "")
endif (ARGP_LIBRARY)

if (ARGP_FOUND)
	if (NOT ARGP_FIND_QUIETLY)
		message(STATUS "Found argp library: ${ARGP_LIBRARY}")
	endif (NOT ARGP_FIND_QUIETLY)
else (ARGP_FOUND)
	set(ARGP_FOUND TRUE)
	message(STATUS "Assuming argp is in libc")
endif (ARGP_FOUND)

mark_as_advanced(ARGP_LIBRARY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_SOURCE_DIR}/config.h)

message(STATUS "Checking availability of argp library - done")
