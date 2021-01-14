# ==============================================================================
# kAFS-user CMake File
# ==============================================================================

SET(EXECUTABLE_OUTPUT_PATH  ${CMAKE_BINARY_DIR}/bin)

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
