/* Copyright (c) 2021 Petr Kulhanek (kulhanek@chemi.muni.cz)
 * Support for kAFS (kernel AFS) adapted from Heimdal libkafs,
 * kafs-client and pam-afs-session.
 */
/*
 * The public APIs of the pam-kafs-session PAM module.
 *
 * Provides the public pam_sm_setcred, pam_sm_open_session, and
 * pam_sm_close_session functions, plus whatever other stubs we need to
 * satisfy PAM.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2006, 2007, 2008, 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <errno.h>
#include <string.h>

#include "internal.h"
#include <kafs-user.h>

/* ============================================================================= */

/*
 * Open a new session. Create a new PAG with k_setpag or k_setpag_shared.
 * A Kerberos PAM module should have previously run to obtain Kerberos tickets
 * (or ticket forwarding should have already happened).
 * Always PAM_SUCCESS except of serious errors in pamkafs_session_open
 */

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
    int             pamret;
    kafs_handle_t*  kafs;

    /* init user */
    kafs = __init_user(pamh);
    if( kafs == NULL ) {
        pamret = PAM_SUCCESS;
        goto done;
    }

    putil_debug(kafs, ">>> pam_sm_open_session flags: %x",flags);

    /* Do nothing unless AFS is available. */
    if( ! k_hasafs() ) {
        putil_debug(kafs, "skipping, AFS apparently not available");
        pamret = PAM_SUCCESS;
        goto done;
    }

    /* shell we ignore user? */
    if( __ignore_user(kafs) != 0 ){
        pamret = PAM_SUCCESS;
        goto done;
    }

    /* create PAG, convert ccache, and create AFS tokens */
    pamret = PAM_SUCCESS;
    if( pamkafs_create_session(kafs) != 0 ){
        pamret = PAM_SESSION_ERR;
    }

done:
    putil_debug(kafs, "<<< pam_sm_open_session");
    __free_user(kafs);
    return pamret;
}

/* ============================================================================= */

/*
 * Don't do anything for authenticate.  We're only an auth module so that we
 * can supply a pam_setcred implementation.
 */
int pam_sm_authenticate(pam_handle_t *pamh UNUSED, int flags UNUSED,
                        int argc UNUSED, const char *argv[] UNUSED)
{
    /*
     * We want to return PAM_IGNORE here, but Linux PAM 0.99.7.1 (at least)
     * has a bug that causes PAM_IGNORE to result in authentication failure
     * when the module is marked [default=done].  So we return PAM_SUCCESS,
     * which is dangerous but works in that case.
     */
    return PAM_SUCCESS;
}

/* ============================================================================= */

/*
 * Calling pam_setcred with PAM_ESTABLISH_CRED is equivalent to opening a new
 * session for our purposes.  With PAM_REFRESH_CRED, we don't call setpag,
 * just run aklog again.  PAM_DELETE_CRED calls unlog.
 */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
    int             pamret;
    kafs_handle_t*  kafs;

    /* init user */
    kafs = __init_user(pamh);
    if( kafs == NULL ) {
        pamret = PAM_IGNORE;
        goto done;
    }

    putil_debug(kafs, ">>> pam_sm_setcred flags: %x",flags);

    /*
     * Do nothing unless AFS is available.  We need to return success here
     * rather than PAM_IGNORE (which would be the more correct return status)
     * since PAM_IGNORE can confuse the Linux PAM library, at least for
     * applications that call pam_setcred without pam_authenticate (possibly
     * because authentication was done some other way), when used with jumps
     * with the [] syntax.  Since we do nothing in this case, and since the
     * stack is already frozen from the auth group, success makes sense.
     */

    /* Do nothing unless AFS is available. */
    if( ! k_hasafs() ) {
        putil_debug(kafs, "skipping, AFS apparently not available");
        pamret = PAM_SUCCESS;
        goto done;
    }

    /* shell we ignore user? */
    if( __ignore_user(kafs) != 0 ){
        pamret = PAM_SUCCESS;
        goto done;
    }

    /*
     * If DELETE_CRED was specified, delete the tokens (if any) and eventually revoke local PAG.
     */
    if (flags & PAM_DELETE_CRED) {
        pamret = PAM_SUCCESS;
        if( pamkafs_destroy_tokens(kafs) != 0 ){
            pamret = PAM_CRED_ERR;
        }
        goto done;
    }

    /* do not modify PAG here, only reinitialize AFS tokens if explicitly requested (screen unlock) */

    /* refresh tokens */
    pamret = PAM_SUCCESS;
    if(  flags & (PAM_REINITIALIZE_CRED | PAM_REFRESH_CRED) ) {
        if( pamkafs_refresh_tokens(kafs) != 0 ){
            pamret = PAM_CRED_ERR;
        }
    }

done:
    putil_debug(kafs, "<<< pam_sm_setcred");
    __free_user(kafs);
    return pamret;
}

/* ============================================================================= */

/*
 * Close a session.  Do nothing here.
 */

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
    kafs_handle_t*  kafs;
    int             pamret;

    /* init user */
    kafs = __init_user(pamh);
    if( kafs == NULL ) {
        pamret = PAM_SUCCESS;
        goto done;
    }

    putil_debug(kafs, ">>> pam_sm_close_session flags: %x",flags);

    /* do nothing here */
    pamret = PAM_SUCCESS;

done:
    putil_debug(kafs, "<<< pam_sm_close_session");
    __free_user(kafs);
    return pamret;
}

/* ============================================================================= */
