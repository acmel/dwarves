# - Find Dwarf
# Find the dwarf.h header from elf utils
#
#  DWARF_INCLUDE_DIR - where to find dwarf.h, etc.
#  DWARF_LIBRARIES   - List of libraries when using elf utils.
#  DWARF_FOUND       - True if fdo found.


IF (DWARF_INCLUDE_DIR)
  # Already in cache, be silent
  SET(DWARF_FIND_QUIETLY TRUE)
ENDIF (DWARF_INCLUDE_DIR)

FIND_PATH(DWARF_INCLUDE_DIR dwarf.h
  /usr/local/include
  /usr/include
)

FIND_PATH(LIBDW_INCLUDE_DIR libdw.h
   /usr/local/include
   /usr/include
   /usr/include/elfutils
   /usr/local/include/elfutils) 

SET(DWARF_NAMES dw elf)
FIND_LIBRARY(DWARF_LIBRARY
  NAMES ${DWARF_NAMES}
  PATHS /usr/lib /usr/local/lib /usr/lib64 /usr/local/lib64
)

IF (DWARF_INCLUDE_DIR AND DWARF_LIBRARY)
   SET(DWARF_FOUND TRUE)
    SET( DWARF_LIBRARIES ${DWARF_LIBRARY} )
ELSE (DWARF_INCLUDE_DIR AND DWARF_LIBRARY)
   SET(DWARF_FOUND FALSE)
   SET( DWARF_LIBRARIES )
ENDIF (DWARF_INCLUDE_DIR AND DWARF_LIBRARY)

IF (DWARF_FOUND)
   IF (NOT DWARF_FIND_QUIETLY)
      MESSAGE(STATUS "Found DWARF: ${DWARF_LIBRARY}")
   ENDIF (NOT DWARF_FIND_QUIETLY)
ELSE (DWARF_FOUND)
   IF (DWARF_FIND_REQUIRED)
      MESSAGE(STATUS "Looked for elf utils libraries named ${DWARFS_NAMES}.")
      MESSAGE(FATAL_ERROR "Could NOT find elf utils libraries")
   ENDIF (DWARF_FIND_REQUIRED)
ENDIF (DWARF_FOUND)

MARK_AS_ADVANCED(
  DWARF_LIBRARY
  DWARF_INCLUDE_DIR
  )
