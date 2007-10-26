project(pahole)

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

add_definitions(-D_GNU_SOURCE)
find_package(DWARF REQUIRED)

_set_fancy(LIB_INSTALL_DIR "${EXEC_INSTALL_PREFIX}${CMAKE_INSTALL_PREFIX}/${__LIB}" "libdir")

set(dwarves_LIB_SRCS dwarves.c)
add_library(dwarves SHARED ${dwarves_LIB_SRCS})
set_target_properties(dwarves PROPERTIES VERSION 1.0.0 SOVERSION 1)
target_link_libraries(dwarves ${DWARF_LIBRARIES})

set(dwarves_emit_LIB_SRCS dwarves_emit.c)
add_library(dwarves_emit SHARED ${dwarves_emit_LIB_SRCS})
set_target_properties(dwarves_emit PROPERTIES VERSION 1.0.0 SOVERSION 1)
target_link_libraries(dwarves_emit ${DWARF_LIBRARIES} dwarves)

set(dwarves_reorganize_LIB_SRCS dwarves_reorganize.c)
add_library(dwarves_reorganize SHARED ${dwarves_reorganize_LIB_SRCS})
set_target_properties(dwarves_reorganize PROPERTIES VERSION 1.0.0 SOVERSION 1)
target_link_libraries(dwarves_reorganize ${DWARF_LIBRARIES} dwarves)

set(codiff_SRCS codiff.c)
add_executable(codiff ${codiff_SRCS})
target_link_libraries(codiff dwarves)

set(ctracer_SRCS ctracer.c)
add_executable(ctracer ${ctracer_SRCS})
target_link_libraries(ctracer dwarves dwarves_emit dwarves_reorganize)

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

set(pfunct_SRCS pfunct.c )
add_executable(pfunct ${pfunct_SRCS})
target_link_libraries(pfunct dwarves)

set(prefcnt_SRCS prefcnt.c)
add_executable(prefcnt ${prefcnt_SRCS})
target_link_libraries(prefcnt dwarves)

set(syscse_SRCS syscse.c)
add_executable(syscse ${syscse_SRCS})
target_link_libraries(syscse dwarves)

install(TARGETS codiff ctracer dtagnames pahole pdwtags
		pfunct pglobal prefcnt syscse RUNTIME DESTINATION
		${CMAKE_INSTALL_PREFIX}/bin)
install(TARGETS dwarves LIBRARY DESTINATION ${LIB_INSTALL_DIR})
install(TARGETS dwarves dwarves_emit dwarves_reorganize LIBRARY DESTINATION ${LIB_INSTALL_DIR})
install(FILES dwarves.h dwarves_emit.h dwarves_reorganize.h DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
install(PROGRAMS ostra/ostra-cg DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
install(FILES ostra/python/ostra.py DESTINATION /usr/share/dwarves/runtime/python)
install(FILES lib/Makefile lib/ctracer_jprobe.c
	      lib/ctracer_relay.c lib/ctracer_relay.h
	DESTINATION /usr/share/dwarves/runtime)
