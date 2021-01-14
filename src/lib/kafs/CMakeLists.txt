# ==============================================================================
# kAFS-user CMake File
# ==============================================================================

SET(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

# idmap ---------------------------------------------------------------------
SET(KAFS_USER_SRC
    kafs-user.c
    kafs_locl.c
    )

IF(KRB5_FLAVOUR STREQUAL "HEIMDAL")
    SET(KAFS_USER_SRC ${KAFS_USER_SRC} rxkad_kdf-hml.c)
ENDIF()

IF(KRB5_FLAVOUR STREQUAL "MIT")
    SET(KAFS_USER_SRC ${KAFS_USER_SRC} rxkad_kdf-mit.c)
ENDIF()

ADD_LIBRARY(${LIBKAFS_NAME} SHARED ${KAFS_USER_SRC})

SET_TARGET_PROPERTIES(${LIBKAFS_NAME} PROPERTIES
                        OUTPUT_NAME ${LIBKAFS_NAME}
                        CLEAN_DIRECT_OUTPUT 1
                        VERSION ${LIBKAFS_VERS}
                        SOVERSION ${LIBKAFS_SO_VERS})

TARGET_LINK_LIBRARIES(${LIBKAFS_NAME}
    ${KRB5_LIBS}
    ${KEYUTILS_LIBS}
    )

INSTALL(TARGETS ${LIBKAFS_NAME}
    DESTINATION ${LIBKAFS_LIB_PATH}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )

# ------------------------------------------------------------------------------
