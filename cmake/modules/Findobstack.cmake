# - Find obstack
# Figure out if obstack is in glibc or if it musl-obstack or elsewhere
#
#  OBSTACK_LIBRARY     - Library to use obstack
#  OBSTACK_FOUND       - True if found.

message(STATUS "Checking availability of obstack library")

INCLUDE(CheckLibraryExists)

if (OBSTACK_LIBRARY)
	# Already in cache, be silent
	set(OBSTACK_FIND_QUIETLY TRUE)
endif (OBSTACK_LIBRARY)

find_library(OBSTACK_LIBRARY
	NAMES obstack
	PATHS /usr/lib /usr/local/lib /usr/lib64 /usr/local/lib64 ~/usr/local/lib ~/usr/local/lib64
)

if (OBSTACK_LIBRARY)
	set(OBSTACK_FOUND TRUE)
	set(OBSTACK_LIBRARY ${OBSTACK_LIBRARY})
	set(CMAKE_REQUIRED_LIBRARIES ${OBSTACK_LIBRARY})
else (OBSTACK_LIBRARY)
	set(OBSTACK_LIBRARY "")
endif (OBSTACK_LIBRARY)

if (OBSTACK_FOUND)
	if (NOT OBSTACK_FIND_QUIETLY)
		message(STATUS "Found obstack library: ${OBSTACK_LIBRARY}")
	endif (NOT OBSTACK_FIND_QUIETLY)
else (OBSTACK_FOUND)
	set(OBSTACK_FOUND TRUE)
	message(STATUS "Assuming obstack is in libc")
endif (OBSTACK_FOUND)

mark_as_advanced(OBSTACK_LIBRARY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_SOURCE_DIR}/config.h)

message(STATUS "Checking availability of obstack library - done")
