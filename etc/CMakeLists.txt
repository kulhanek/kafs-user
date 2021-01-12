# ==============================================================================
# kAFS-user CMake File
# ==============================================================================

# systemd units

INSTALL(FILES afs.mount kafs-init.service
    DESTINATION ${SYSTEMD_SYSTEM_CONF}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )

# ------------------------------------------------------------------------------

# PAM module configuration

INSTALL(FILES kafs-session
    DESTINATION ${PAM_CONFIG_DIR}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )

# ------------------------------------------------------------------------------
