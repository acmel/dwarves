project(pahole)

# where to look first for cmake modules,
# before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

find_package(DWARF REQUIRED)
SET(CMAKE_BUILD_TYPE Debug)

SET(classes_LIB_SRCS classes.c)
ADD_LIBRARY(classes SHARED ${classes_LIB_SRCS})

SET(codiff_SRCS codiff.c)
ADD_EXECUTABLE(codiff ${codiff_SRCS})
TARGET_LINK_LIBRARIES(codiff classes ${DWARF_LIBRARIES})

SET(pahole_SRCS pahole.c)
ADD_EXECUTABLE(pahole ${pahole_SRCS})
TARGET_LINK_LIBRARIES(pahole classes ${DWARF_LIBRARIES})

SET(pfunct_SRCS pfunct.c )
ADD_EXECUTABLE(pfunct ${pfunct_SRCS})
TARGET_LINK_LIBRARIES(pfunct classes ${DWARF_LIBRARIES})

SET(prefcnt_SRCS prefcnt.c)
ADD_EXECUTABLE(prefcnt ${prefcnt_SRCS})
TARGET_LINK_LIBRARIES(prefcnt classes ${DWARF_LIBRARIES})
