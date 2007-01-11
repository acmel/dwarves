project(pahole)

# where to look first for cmake modules,
# before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

SET(CMAKE_BUILD_TYPE debug)

find_package(DWARF REQUIRED)

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

SET(pfunct_SRCS pfunct.c )
ADD_EXECUTABLE(pfunct ${pfunct_SRCS})
TARGET_LINK_LIBRARIES(pfunct dwarves ${DWARF_LIBRARIES})

SET(prefcnt_SRCS prefcnt.c)
ADD_EXECUTABLE(prefcnt ${prefcnt_SRCS})
TARGET_LINK_LIBRARIES(prefcnt dwarves ${DWARF_LIBRARIES})
