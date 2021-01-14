# ==============================================================================
# kAFS-user CMake File
# ==============================================================================

SET(EXECUTABLE_OUTPUT_PATH  ${CMAKE_BINARY_DIR}/bin)

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
