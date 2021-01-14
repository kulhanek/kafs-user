# ==============================================================================
# kAFS-user CMake File
# ==============================================================================

SET(EXECUTABLE_OUTPUT_PATH  ${CMAKE_BINARY_DIR}/bin)

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
