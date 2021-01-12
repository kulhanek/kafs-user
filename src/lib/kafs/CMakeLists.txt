# ==============================================================================
# kAFS-user CMake File
# ==============================================================================

SET(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

# idmap ---------------------------------------------------------------------
SET(KAFS_USER_SRC
    kafs-user.c
    kafs_locl.c
    rxkad_kdf.c
    )

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

INSTALL(TARGETS     ${LIBKAFS_NAME}
    DESTINATION ${USER_LIB_PATH}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )

# ------------------------------------------------------------------------------
