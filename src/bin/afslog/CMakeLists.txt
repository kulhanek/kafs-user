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
