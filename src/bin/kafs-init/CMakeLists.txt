# ==============================================================================
# kAFS-user CMake File
# ==============================================================================

SET(EXECUTABLE_OUTPUT_PATH  ${CMAKE_BINARY_DIR}/bin)

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
