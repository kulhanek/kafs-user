# ==============================================================================
# kAFS-user CMake File
# ==============================================================================

SET(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)
SET(CMAKE_SHARED_LIBRARY_PREFIX "")

# idmap ---------------------------------------------------------------------
SET(PAM_KAFS_SESSION_SRC
    public.c
    local.c
    )

ADD_LIBRARY(${PAM_KAFS_SESSION} SHARED ${PAM_KAFS_SESSION_SRC})

TARGET_LINK_LIBRARIES(${PAM_KAFS_SESSION}
    ${LIBKAFS_NAME}
    ${PAM_LIBS}
    )

INSTALL(TARGETS     ${PAM_KAFS_SESSION}
        DESTINATION ${PAM_MODULE_PATH}
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
        )

# ------------------------------------------------------------------------------
