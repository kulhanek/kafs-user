# ==============================================================================
# kAFS-user CMake File
# ==============================================================================

SET(EXECUTABLE_OUTPUT_PATH  ${CMAKE_BINARY_DIR}/bin)

# ------------------------------------------------------------------------------

SET(AFSLOG_SRC
    afslog.c
    )

ADD_EXECUTABLE(afslog.kafs ${AFSLOG_SRC})

TARGET_LINK_LIBRARIES(afslog.kafs
    ${LIBKAFS_NAME}
    ${KRB5_LIBS}
    )

INSTALL(TARGETS afslog.kafs
    DESTINATION ${USER_BIN_PATH}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    )

# ------------------------------------------------------------------------------

SET(UNLOG_SRC
    unlog.c
    )

ADD_EXECUTABLE(unlog.kafs ${UNLOG_SRC})

TARGET_LINK_LIBRARIES(unlog.kafs
    ${LIBKAFS_NAME}
    )

INSTALL(TARGETS unlog.kafs
    DESTINATION ${USER_BIN_PATH}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    )

# ------------------------------------------------------------------------------

SET(TOKENS_SRC
    tokens.c
    )

ADD_EXECUTABLE(tokens.kafs ${TOKENS_SRC})

TARGET_LINK_LIBRARIES(tokens.kafs
    ${LIBKAFS_NAME}
    )

INSTALL(TARGETS tokens.kafs
    DESTINATION ${USER_BIN_PATH}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    )

# ------------------------------------------------------------------------------

SET(PAGSH_SRC
    pagsh.c
    )

ADD_EXECUTABLE(pagsh.kafs ${PAGSH_SRC})

TARGET_LINK_LIBRARIES(pagsh.kafs
    ${LIBKAFS_NAME}
    )

INSTALL(TARGETS pagsh.kafs
    DESTINATION ${USER_BIN_PATH}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    )

# ------------------------------------------------------------------------------

SET(KINIT_SRC
    kinit.c
    )

ADD_EXECUTABLE(kinit.kafs ${KINIT_SRC})

TARGET_LINK_LIBRARIES(kinit.kafs
    ${LIBKAFS_NAME}
    ${NTLM_LIBS}
    ${KRB5_LIBS}
    )

INSTALL(TARGETS kinit.kafs
    DESTINATION ${USER_BIN_PATH}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    )

# ------------------------------------------------------------------------------

SET(KAFS_INIT_SRC
    kafs-init.c
    )

ADD_EXECUTABLE(kafs-init ${KAFS_INIT_SRC})

TARGET_LINK_LIBRARIES(kafs-init
    ${LIBKAFS_NAME}
    )

INSTALL(TARGETS kafs-init
    DESTINATION ${USER_LIBEXEC_PATH}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    )

# ------------------------------------------------------------------------------
