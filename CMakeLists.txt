# ==============================================================================
# kAFS-user CMake File
# ==============================================================================

CMAKE_MINIMUM_REQUIRED(VERSION 2.8.0 FATAL_ERROR)
#SET(CMAKE_VERBOSE_MAKEFILE ON)

# ==============================================================================
# conditional setup ------------------------------------------------------------
# ==============================================================================

SET(ENABLE_UTILS  ON CACHE BOOL "Build and install user utilities (afslog, unlog, ..).")
SET(ENABLE_USETUP ON CACHE BOOL "Build kafs")
SET(ENABLE_UPAM   ON CACHE BOOL "Should the static version of hipoly library be built?")

# ==============================================================================
# project setup ----------------------------------------------------------------
# ==============================================================================

ENABLE_LANGUAGE(C)

# ==============================================================================
# install setup ----------------------------------------------------------------
# ==============================================================================

# installation paths
SET(USER_BIN_PATH       "/usr/bin")
SET(USER_LIBEXEC_PATH   "/usr/libexec")
SET(SYSTEMD_SYSTEM_CONF "/lib/systemd/system")
SET(PAM_CONFIG_DIR      "/usr/share/pam-configs")
SET(PAM_MODULE_PATH     "/lib/x86_64-linux-gnu/security/")
SET(KAFS_CONF           "/etc/kafs-user")

SET(LIBKAFS_NAME        "kafs")
SET(LIBKAFS_SO_VERS     "0")
SET(LIBKAFS_VERS        "0.5.1")

SET(PAM_KAFS_SESSION    "pam_kafs_session")

# this works in cmake 3.11
set(CMAKE_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS
     OWNER_READ OWNER_WRITE OWNER_EXECUTE
     GROUP_READ GROUP_EXECUTE
     WORLD_READ WORLD_EXECUTE
   )

INSTALL(DIRECTORY
    DESTINATION ${KAFS_CONF}
    DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    )

# ==============================================================================
# dependencies -----------------------------------------------------------------
# ==============================================================================

SET(KRB5_FLAVOUR "MIT")

IF(KRB5_FLAVOUR STREQUAL "HEIMDAL")

    # Heimdal Krb5
    INCLUDE_DIRECTORIES(/usr/include/heimdal SYSTEM)
    LINK_DIRECTORIES(/usr/lib/x86_64-linux-gnu/heimdal)

    SET(NTLM_LIBS           "-lheimntlm")
    SET(KRB5_LIBS           "-lkrb5 -lhcrypto -lroken")
    SET(KEYUTILS_LIBS       "-lkeyutils")
    SET(PAM_LIBS            "-lpam")

    SET(LIBKAFS_LIB_PATH    "/lib/x86_64-linux-gnu/kafs-user/heimdal")

    ADD_DEFINITIONS(-DHEIMDAL)
ENDIF()

IF(KRB5_FLAVOUR STREQUAL "MIT")

    # MIT Krb5
    INCLUDE_DIRECTORIES(/usr/include/mit SYSTEM)
    LINK_DIRECTORIES(/usr/lib/x86_64-linux-gnu)

    SET(KRB5_LIBS           "-lkrb5")
    SET(KEYUTILS_LIBS       "-lkeyutils")
    SET(PAM_LIBS            "-lpam")

    SET(LIBKAFS_LIB_PATH    "/lib/x86_64-linux-gnu/kafs-user/mit")
ENDIF()

# ------------------------------------------------------------------------------

# use, i.e. don't skip the full RPATH for the build tree
SET(CMAKE_SKIP_BUILD_RPATH  FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

# the RPATH to be used when installing
SET(CMAKE_INSTALL_RPATH "${LIBKAFS_LIB_PATH}")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)

# ==============================================================================
# compiler setups --------------------------------------------------------------
# ==============================================================================

IF(NOT DEFINED COMPOSITE_PROJECT)
    SET(CMAKE_C_FLAGS_RELEASE "-O2 -fPIC")
    SET(CMAKE_C_FLAGS_DEBUG "-g -O0 -fPIC -Wall -Werror -pedantic-errors -Wundef -Wno-long-long")
    #SET(CMAKE_BUILD_TYPE Release)
    SET(CMAKE_BUILD_TYPE Debug)
ENDIF(NOT DEFINED COMPOSITE_PROJECT)

# ==============================================================================
# project subdirectories  ------------------------------------------------------
# ==============================================================================

ADD_SUBDIRECTORY(etc)
ADD_SUBDIRECTORY(src)
