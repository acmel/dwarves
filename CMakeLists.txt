project(pahole C)
cmake_minimum_required(VERSION 2.8.8)
cmake_policy(SET CMP0005 NEW)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}
		    ${CMAKE_CURRENT_SOURCE_DIR}
		    ${CMAKE_CURRENT_SOURCE_DIR}/lib/bpf/include/uapi)

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

add_definitions(-D_GNU_SOURCE -DDWARVES_VERSION="v1.18")
find_package(DWARF REQUIRED)
find_package(ZLIB REQUIRED)

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
if(NOT EXISTS "${PROJECT_SOURCE_DIR}/lib/bpf/src/btf.h")
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

file(GLOB libbpf_sources "lib/bpf/src/*.c")
add_library(bpf OBJECT ${libbpf_sources})
set_property(TARGET bpf PROPERTY POSITION_INDEPENDENT_CODE 1)
target_include_directories(bpf PRIVATE
			   ${CMAKE_CURRENT_SOURCE_DIR}/lib/bpf/include
			   ${CMAKE_CURRENT_SOURCE_DIR}/lib/bpf/include/uapi)

set(dwarves_LIB_SRCS dwarves.c dwarves_fprintf.c gobuffer strings
		     ctf_encoder.c ctf_loader.c libctf.c btf_encoder.c btf_loader.c libbtf.c
		     dwarf_loader.c dutil.c elf_symtab.c rbtree.c)
add_library(dwarves SHARED ${dwarves_LIB_SRCS} $<TARGET_OBJECTS:bpf>)
set_target_properties(dwarves PROPERTIES VERSION 1.0.0 SOVERSION 1)
set_target_properties(dwarves PROPERTIES INTERFACE_LINK_LIBRARIES "")
target_include_directories(dwarves PRIVATE
			   ${CMAKE_CURRENT_SOURCE_DIR}/lib/bpf/include/uapi)
target_link_libraries(dwarves ${DWARF_LIBRARIES} ${ZLIB_LIBRARIES})

set(dwarves_emit_LIB_SRCS dwarves_emit.c)
add_library(dwarves_emit SHARED ${dwarves_emit_LIB_SRCS})
set_target_properties(dwarves_emit PROPERTIES VERSION 1.0.0 SOVERSION 1)
target_link_libraries(dwarves_emit dwarves)

set(dwarves_reorganize_LIB_SRCS dwarves_reorganize.c)
add_library(dwarves_reorganize SHARED ${dwarves_reorganize_LIB_SRCS})
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
install(TARGETS dwarves LIBRARY DESTINATION ${LIB_INSTALL_DIR})
install(TARGETS dwarves dwarves_emit dwarves_reorganize LIBRARY DESTINATION ${LIB_INSTALL_DIR})
install(FILES dwarves.h dwarves_emit.h dwarves_reorganize.h
	      dutil.h gobuffer.h list.h rbtree.h pahole_strings.h
	      btf_encoder.h config.h ctf_encoder.h ctf.h
	      elfcreator.h elf_symtab.h hash.h libbtf.h libctf.h
	DESTINATION ${CMAKE_INSTALL_PREFIX}/include/dwarves/)
install(FILES man-pages/pahole.1 DESTINATION ${CMAKE_INSTALL_PREFIX}/share/man/man1/)
install(PROGRAMS ostra/ostra-cg DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
install(PROGRAMS btfdiff fullcircle DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
install(FILES ostra/python/ostra.py DESTINATION ${CMAKE_INSTALL_PREFIX}/share/dwarves/runtime/python)
install(FILES lib/Makefile lib/ctracer_relay.c lib/ctracer_relay.h lib/linux.blacklist.cu
	DESTINATION ${CMAKE_INSTALL_PREFIX}/share/dwarves/runtime)
