project(pahole)

# Try to parse this later, Helio just showed me a KDE4 example to support
# x86-64 builds.
# the following are directories where stuff will be installed to
set(__LIB "" CACHE STRING "Define suffix of directory name (32/64)" )

macro(_SET_FANCY _var _value _comment)
	if (NOT DEFINED ${_var})
		set(${_var} ${_value})
	else (NOT DEFINED ${_var})
		set(${_var} "${${_var}}" CACHE PATH "${_comment}")
	endif (NOT DEFINED ${_var})
endmacro(_SET_FANCY)

# where to look first for cmake modules,
# before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

SET(CMAKE_BUILD_TYPE debug)

find_package(DWARF REQUIRED)

_SET_FANCY(LIB_INSTALL_DIR "${EXEC_INSTALL_PREFIX}/usr/${__LIB}" "libdir")

SET(dwarves_LIB_SRCS dwarves.c)
ADD_LIBRARY(dwarves SHARED ${dwarves_LIB_SRCS})
SET_TARGET_PROPERTIES(dwarves PROPERTIES VERSION 1.0.0 SOVERSION 1)

SET(codiff_SRCS codiff.c)
ADD_EXECUTABLE(codiff ${codiff_SRCS})
TARGET_LINK_LIBRARIES(codiff dwarves ${DWARF_LIBRARIES})

SET(ctracer_SRCS ctracer.c)
ADD_EXECUTABLE(ctracer ${ctracer_SRCS})
TARGET_LINK_LIBRARIES(ctracer dwarves ${DWARF_LIBRARIES})

SET(dtagnames_SRCS dtagnames.c)
ADD_EXECUTABLE(dtagnames ${dtagnames_SRCS})
TARGET_LINK_LIBRARIES(dtagnames dwarves ${DWARF_LIBRARIES})

SET(pahole_SRCS pahole.c)
ADD_EXECUTABLE(pahole ${pahole_SRCS})
TARGET_LINK_LIBRARIES(pahole dwarves ${DWARF_LIBRARIES})

SET(pdwtags_SRCS pdwtags.c)
ADD_EXECUTABLE(pdwtags ${pdwtags_SRCS})
TARGET_LINK_LIBRARIES(pdwtags dwarves ${DWARF_LIBRARIES})

SET(pglobal_SRCS pglobal.c)
ADD_EXECUTABLE(pglobal ${pglobal_SRCS})
TARGET_LINK_LIBRARIES(pglobal dwarves ${DWARF_LIBRARIES})

SET(pfunct_SRCS pfunct.c )
ADD_EXECUTABLE(pfunct ${pfunct_SRCS})
TARGET_LINK_LIBRARIES(pfunct dwarves ${DWARF_LIBRARIES})

SET(prefcnt_SRCS prefcnt.c)
ADD_EXECUTABLE(prefcnt ${prefcnt_SRCS})
TARGET_LINK_LIBRARIES(prefcnt dwarves ${DWARF_LIBRARIES})

INSTALL(TARGETS codiff ctracer dtagnames pahole pdwtags
		pfunct pglobal prefcnt RUNTIME DESTINATION /usr/bin)
INSTALL(TARGETS dwarves LIBRARY DESTINATION ${LIB_INSTALL_DIR})
INSTALL(FILES dwarves.h DESTINATION /usr/include)
INSTALL(FILES lib/Makefile lib/ctracer_jprobe.c DESTINATION ${LIB_INSTALL_DIR}/ctracer)
