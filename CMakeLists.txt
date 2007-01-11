project(pahole)

# where to look first for cmake modules,
# before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

SET(CMAKE_BUILD_TYPE debug)

find_package(DWARF REQUIRED)

SET(pahole_LIB_SRCS classes.c)
ADD_LIBRARY(pahole SHARED ${pahole_LIB_SRCS})

SET(codiff_SRCS codiff.c)
ADD_EXECUTABLE(codiff ${codiff_SRCS})
TARGET_LINK_LIBRARIES(codiff pahole ${DWARF_LIBRARIES})

SET(ctracer_SRCS ctracer.c)
ADD_EXECUTABLE(ctracer ${ctracer_SRCS})
TARGET_LINK_LIBRARIES(ctracer pahole ${DWARF_LIBRARIES})

SET(dtagnames_SRCS dtagnames.c)
ADD_EXECUTABLE(dtagnames ${dtagnames_SRCS})
TARGET_LINK_LIBRARIES(dtagnames pahole ${DWARF_LIBRARIES})

SET(pahole_SRCS pahole.c)
ADD_EXECUTABLE(pahole ${pahole_SRCS})
TARGET_LINK_LIBRARIES(pahole pahole ${DWARF_LIBRARIES})

SET(pfunct_SRCS pfunct.c )
ADD_EXECUTABLE(pfunct ${pfunct_SRCS})
TARGET_LINK_LIBRARIES(pfunct pahole ${DWARF_LIBRARIES})

SET(prefcnt_SRCS prefcnt.c)
ADD_EXECUTABLE(prefcnt ${prefcnt_SRCS})
TARGET_LINK_LIBRARIES(prefcnt pahole ${DWARF_LIBRARIES})
