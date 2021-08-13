project(pahole C)
cmake_minimum_required(VERSION 2.8.12)
cmake_policy(SET CMP0005 NEW)

option(LIBBPF_EMBEDDED "Use the embedded version of libbpf instead of searching it via pkg-config" ON)
if (NOT LIBBPF_EMBEDDED)
	find_package(PkgConfig REQUIRED)
	if(PKGCONFIG_FOUND)
		pkg_check_modules(LIBBPF REQUIRED libbpf>=0.4.0)
	endif()
endif()

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}
		    ${CMAKE_CURRENT_SOURCE_DIR})
if(NOT LIBBPF_FOUND)
	# Allows to use 'system' style #include with both embedded and system libbpf
	INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/lib/include)
	INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/lib/bpf/include/uapi)
else()
	INCLUDE_DIRECTORIES(${LIBBPF_INCLUDE_DIRS})
	LINK_DIRECTORIES(${LIBBPF_LIBRARY_DIRS})
endif()

# Try to parse this later, Helio just showed me a KDE4 example to support
# x86-64 builds.
# the following are directories where stuff will be installed to
set(__LIB "" CACHE STRING "Define suffix of directory name (32/64)" )

macro(_set_fancy _var _value _comment)
	if (NOT DEFINED ${_var})
		set(${_var} ${_value})
	else (NOT DEFINED ${_var})
		set(${_var} "${${_var}}" CACHE PATH "${_comment}")
	endif (NOT DEFINED ${_var})
endmacro(_set_fancy)

# where to look first for cmake modules,
# before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

if (NOT CMAKE_BUILD_TYPE)
	set (CMAKE_BUILD_TYPE Debug CACHE STRING
	     "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
	     FORCE)
endif (NOT CMAKE_BUILD_TYPE)

set(CMAKE_C_FLAGS_DEBUG "-Wall -Werror -ggdb -O0")
set(CMAKE_C_FLAGS_RELEASE "-Wall -O2")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")

if (NOT DEFINED BUILD_SHARED_LIBS)
	set (BUILD_SHARED_LIBS ON)
	message(STATUS "Setting BUILD_SHARED_LIBS = ${BUILD_SHARED_LIBS}")
endif (NOT DEFINED BUILD_SHARED_LIBS)

# Just for grepping, DWARVES_VERSION isn't used anywhere anymore
# add_definitions(-D_GNU_SOURCE -DDWARVES_VERSION="v1.22")
add_definitions(-D_GNU_SOURCE -DDWARVES_MAJOR_VERSION=1)
add_definitions(-D_GNU_SOURCE -DDWARVES_MINOR_VERSION=22)
find_package(DWARF REQUIRED)
find_package(ZLIB REQUIRED)
find_package(argp REQUIRED)
find_package(obstack REQUIRED)

# make sure git submodule(s) are checked out
find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
	# Update submodules as needed
	option(GIT_SUBMODULE "Check submodules during build" ON)
	if(GIT_SUBMODULE)
		message(STATUS "Submodule update")
		execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
				WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
				RESULT_VARIABLE GIT_SUBMOD_RESULT)
		if(NOT GIT_SUBMOD_RESULT EQUAL "0")
			message(FATAL_ERROR "git submodule update --init failed with ${GIT_SUBMOD_RESULT}, please checkout submodules")
		else()
			message(STATUS "Submodule update - done")
		endif()
	endif()
endif()
if(NOT LIBBPF_FOUND AND NOT EXISTS "${PROJECT_SOURCE_DIR}/lib/bpf/src/btf.h")
	message(FATAL_ERROR "The submodules were not downloaded! GIT_SUBMODULE was turned off or failed. Please update submodules and try again.")
endif()

_set_fancy(LIB_INSTALL_DIR "${EXEC_INSTALL_PREFIX}${CMAKE_INSTALL_PREFIX}/${__LIB}" "libdir")

# libbpf uses reallocarray, which is not available in all versions of glibc
# libbpf's include/tools/libc_compat.h provides implementation, but needs
# COMPACT_NEED_REALLOCARRAY to be set
INCLUDE(CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES(
"
#define _GNU_SOURCE
#include <stdlib.h>
int main(void)
{
        return !!reallocarray(NULL, 1, 1);
}
" HAVE_REALLOCARRAY_SUPPORT)
if (NOT HAVE_REALLOCARRAY_SUPPORT)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCOMPAT_NEED_REALLOCARRAY")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64")

if (NOT LIBBPF_FOUND)
	file(GLOB libbpf_sources "lib/bpf/src/*.c")
	add_library(bpf OBJECT ${libbpf_sources})
	set_property(TARGET bpf PROPERTY POSITION_INDEPENDENT_CODE 1)
	target_include_directories(bpf PRIVATE
				   ${CMAKE_CURRENT_SOURCE_DIR}/lib/bpf/include
				   ${CMAKE_CURRENT_SOURCE_DIR}/lib/bpf/include/uapi)
endif()

set(dwarves_LIB_SRCS dwarves.c dwarves_fprintf.c gobuffer.c
		     ctf_loader.c libctf.c btf_encoder.c btf_loader.c
		     dwarf_loader.c dutil.c elf_symtab.c rbtree.c)
if (NOT LIBBPF_FOUND)
	list(APPEND dwarves_LIB_SRCS $<TARGET_OBJECTS:bpf>)
endif()
add_library(dwarves ${dwarves_LIB_SRCS})
set_target_properties(dwarves PROPERTIES VERSION 1.0.0 SOVERSION 1)
set_target_properties(dwarves PROPERTIES INTERFACE_LINK_LIBRARIES "")
target_link_libraries(dwarves ${DWARF_LIBRARIES} ${ZLIB_LIBRARIES} ${LIBBPF_LIBRARIES} ${ARGP_LIBRARY} ${OBSTACK_LIBRARY})

set(dwarves_emit_LIB_SRCS dwarves_emit.c)
add_library(dwarves_emit ${dwarves_emit_LIB_SRCS})
set_target_properties(dwarves_emit PROPERTIES VERSION 1.0.0 SOVERSION 1)
target_link_libraries(dwarves_emit dwarves)

set(dwarves_reorganize_LIB_SRCS dwarves_reorganize.c)
add_library(dwarves_reorganize ${dwarves_reorganize_LIB_SRCS})
set_target_properties(dwarves_reorganize PROPERTIES VERSION 1.0.0 SOVERSION 1)
target_link_libraries(dwarves_reorganize dwarves)

set(codiff_SRCS codiff.c)
add_executable(codiff ${codiff_SRCS})
target_link_libraries(codiff dwarves)

set(ctracer_SRCS ctracer.c)
add_executable(ctracer ${ctracer_SRCS})
target_link_libraries(ctracer dwarves dwarves_emit dwarves_reorganize ${ELF_LIBRARY})

set(dtagnames_SRCS dtagnames.c)
add_executable(dtagnames ${dtagnames_SRCS})
target_link_libraries(dtagnames dwarves)

set(pahole_SRCS pahole.c)
add_executable(pahole ${pahole_SRCS})
target_link_libraries(pahole dwarves dwarves_reorganize)

set(pdwtags_SRCS pdwtags.c)
add_executable(pdwtags ${pdwtags_SRCS})
target_link_libraries(pdwtags dwarves)

set(pglobal_SRCS pglobal.c)
add_executable(pglobal ${pglobal_SRCS})
target_link_libraries(pglobal dwarves)

set(pfunct_SRCS pfunct.c)
add_executable(pfunct ${pfunct_SRCS})
target_link_libraries(pfunct dwarves dwarves_emit ${ELF_LIBRARY})

set(prefcnt_SRCS prefcnt.c)
add_executable(prefcnt ${prefcnt_SRCS})
target_link_libraries(prefcnt dwarves)

set(scncopy_SRCS scncopy.c elfcreator.c)
add_executable(scncopy ${scncopy_SRCS})
target_link_libraries(scncopy dwarves ${ELF_LIBRARY})

set(syscse_SRCS syscse.c)
add_executable(syscse ${syscse_SRCS})
target_link_libraries(syscse dwarves)

install(TARGETS codiff ctracer dtagnames pahole pdwtags
		pfunct pglobal prefcnt scncopy syscse RUNTIME DESTINATION
		${CMAKE_INSTALL_PREFIX}/bin)
install(TARGETS dwarves LIBRARY DESTINATION ${LIB_INSTALL_DIR} ARCHIVE DESTINATION ${LIB_INSTALL_DIR})
install(TARGETS dwarves dwarves_emit dwarves_reorganize LIBRARY DESTINATION ${LIB_INSTALL_DIR} ARCHIVE DESTINATION ${LIB_INSTALL_DIR})
install(FILES dwarves.h dwarves_emit.h dwarves_reorganize.h
	      dutil.h gobuffer.h list.h rbtree.h
	      btf_encoder.h config.h ctf.h
	      elfcreator.h elf_symtab.h hash.h libctf.h
	DESTINATION ${CMAKE_INSTALL_PREFIX}/include/dwarves/)
install(FILES man-pages/pahole.1 DESTINATION ${CMAKE_INSTALL_PREFIX}/share/man/man1/)
install(PROGRAMS ostra/ostra-cg DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
install(PROGRAMS btfdiff fullcircle DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
install(FILES ostra/python/ostra.py DESTINATION ${CMAKE_INSTALL_PREFIX}/share/dwarves/runtime/python)
install(FILES lib/Makefile lib/ctracer_relay.c lib/ctracer_relay.h lib/linux.blacklist.cu
	DESTINATION ${CMAKE_INSTALL_PREFIX}/share/dwarves/runtime)
