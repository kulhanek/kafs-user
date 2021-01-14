# ==============================================================================
# kAFS-user CMake File
# ==============================================================================

SET(EXECUTABLE_OUTPUT_PATH  ${CMAKE_BINARY_DIR}/bin)

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
