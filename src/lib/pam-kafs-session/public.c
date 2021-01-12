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
 */

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
    const void*     dummy;
    int             pamret;
    int             already_afslog;
    kafs_handle_t*  kafs = NULL;

    putil_notice(pamh, ">>> pam_sm_open_session flags: %x",flags);

    /* Do nothing unless AFS is available. */
    if( ! k_hasafs() ) {
        putil_notice(pamh, "skipping, AFS apparently not available");
        pamret = PAM_IGNORE;
        goto done;
    }

    /* init user */
    kafs = __init_user(pamh);
    if( kafs == NULL ) {
        putil_err(pamh, "no suitable user");
        pamret = PAM_IGNORE;
        goto done;
    }

    /* shell we ignore user? */
    if( __ignore_user(kafs) == 1 ){
        pamret = PAM_SUCCESS;
        goto done;
    }

    /* was afslog already called? */
    already_afslog = 0;
    if( pam_get_data(pamh, PAMAFS_MODULE_NAME, &dummy) == PAM_SUCCESS ){
        already_afslog = 1;
    }

    /* become target user for subsequent operations */
    if( __enter_user(kafs) > 0 ){
        pamret = PAM_SESSION_ERR;
        goto done;
    }

    int err = 0;
    /* create PAG if necessary */
    if( k_haspag() == 0 ){
        if( _pamafs_shared_pag == 1 ) {
            if( k_setpag_shared() != 0 ){
                putil_err(pamh, "unable to create shared PAG");
                err = 1;
            }
        } else {
            if( k_setpag() != 0 ){
                putil_err(pamh, "unable to create PAG");
                err = 1;
            }
        }
        if( err == 0 ) already_afslog = 0; /* PAG created - we need to afslog */
    }
    /* afslog */
    if( ( already_afslog == 0 ) && (err == 0) ) {
        if( pamkafs_afslog(pamh) != 0 ) {
            putil_err(pamh, "unable to afslog");
            err = 2;
        }
    }

    /* restore service user */
    if( __leave_user(kafs) ){
        pamret = PAM_SESSION_ERR;
        goto done;
    }

    /* record success */
    if( (already_afslog == 0) && (err == 0 ) ){
        if( pam_set_data(pamh, PAMAFS_MODULE_NAME, (char *) "yes", NULL) != PAM_SUCCESS ){
            putil_err(pamh, "cannot set success data");
            pamret = PAM_SESSION_ERR;
            goto done;
        }
    }

    pamret = PAM_SUCCESS;

done:
    __free_user(kafs);
    putil_notice(pamh, "<<< pam_sm_open_session");
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
    const void*     dummy;
    int             pamret;
    int             already_afslog;
    kafs_handle_t*  kafs = NULL;

    putil_notice(pamh, ">>> pam_sm_setcred flags: %x",flags);

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
        putil_notice(pamh, "skipping, AFS apparently not available");
        pamret = PAM_SUCCESS;
        goto done;
    }

    /* init user */
    kafs = __init_user(pamh);
    if( kafs == NULL ) {
        putil_err(pamh, "no suitable user");
        pamret = PAM_SUCCESS;
        goto done;
    }

    /* shell we ignore user? */
    if( __ignore_user(kafs) == 1 ){
        pamret = PAM_SUCCESS;
        goto done;
    }

    /* was afslog already called? */
    already_afslog = 0;
    if( pam_get_data(pamh, PAMAFS_MODULE_NAME, &dummy) == PAM_SUCCESS ){
        already_afslog = 1;
    }

    /*
     * If DELETE_CRED was specified, delete the tokens (if any).  Similarly
     * return PAM_SUCCESS here instead of PAM_IGNORE.
     */
    if (flags & PAM_DELETE_CRED) {
        if( (already_afslog == 0) || (_pamafs_shared_pag == 1) ){
            pamret = PAM_SUCCESS;   /* AFS tokens already destroyed or shared PAG */
            goto done;
        }

        /* become target user for subsequent operations */
        if( __enter_user(kafs) > 0 ){
            pamret = PAM_CRED_ERR;
            goto done;
        }

        /* destroy all AFS tokens */
        int err = k_unlog();
        if( err != 0 ){
            putil_err(pamh, "unable to unlog");
        }

        /* restore service user */
        if( __leave_user(kafs) ){
            pamret = PAM_CRED_ERR;
            goto done;
        }

        /* remove module data */
        if( err == 0 ){
            if( pam_set_data(pamh, PAMAFS_MODULE_NAME, NULL, NULL) != PAM_SUCCESS ){
                putil_err(pamh, "unable to remove module data");
                pamret = PAM_CRED_ERR;
                goto done;
            }
        }

        pamret = PAM_SUCCESS;
        goto done;
    }

    /*
     * We're acquiring tokens.  See if we already have done this and don't do
     * it again if we have unless we were explicitly told to reinitialize.  If
     * we're reinitializing, we may be running in a screen saver or the like
     * and should use the existing PAG, so don't create a new PAG.
     */

    /* become target user for subsequent operations */
    if( __enter_user(kafs) > 0 ){
        pamret = PAM_CRED_ERR;
        goto done;
    }

    int err = 0;
    /* create PAG if necessary
     * k_setpag_shared cannot be called if the PAG has been already created (normally it works, but not here :-(
     * keyctl_join_session_keyring (in k_setpag_shared) returns the zero key and __leave_user fails :-(
     * perhaps wrong permissions after the first keyctl_setperm?
     *  Jan 12 16:33:00 pes sshd[31860]: pam_kafs_session(sshd:setcred): >>> pam_sm_setcred
     *  Jan 12 16:33:00 pes sshd[31860]: pam_kafs_session(sshd:setcred): >>> __enter_user 0 -> 1001
     *  Jan 12 16:33:00 pes sshd[31860]: pam_kafs_session(sshd:setcred): unable to create PAG
     *  Jan 12 16:33:00 pes sshd[31860]: pam_kafs_session(sshd:setcred): <<< __leave_user 0 <- 1001
     *  Jan 12 16:33:00 pes sshd[31860]: pam_kafs_session(sshd:setcred): __leave_user: unable to change UID back to 0
     *  Jan 12 16:33:00 pes sshd[31860]: pam_kafs_session(sshd:setcred): errno: Operation not permitted
     *  Jan 12 16:33:00 pes sshd[31860]: pam_kafs_session(sshd:setcred): <<< pam_sm_setcred
     */
    if( k_haspag() == 0 ){
        if( _pamafs_shared_pag == 1 ) {
            if( k_setpag_shared() != 0 ){
                putil_err(pamh, "unable to create shared PAG");
                err = 1;
            }
        } else {
            if( k_setpag() != 0 ){
                putil_err(pamh, "unable to create PAG");
                err = 1;
            }
        }
        if( err == 0 ) already_afslog = 0; /* PAG created - we need to afslog */
    }

    if( flags & (PAM_REINITIALIZE_CRED | PAM_REFRESH_CRED) ){
        already_afslog = 0; /* recreate as requested */
    }

    /* afslog */
    if( ( already_afslog == 0 ) && (err == 0) ) {
        if( pamkafs_afslog(pamh) != 0 ) {
            putil_err(pamh, "unable to afslog");
            err = 2;
        }
    }

    /* restore service user */
    if( __leave_user(kafs) ){
        pamret = PAM_CRED_ERR;
        goto done;
    }

    /* record success */
    if( (already_afslog == 0) && (err == 0 ) ){
        if( pam_set_data(pamh, PAMAFS_MODULE_NAME, (char *) "yes", NULL) != PAM_SUCCESS ){
            putil_err(pamh, "cannot set success data");
            pamret = PAM_CRED_ERR;
            goto done;
        }
    }
    pamret = PAM_SUCCESS;

done:
    __free_user(kafs);
    putil_notice(pamh, "<<< pam_sm_setcred");
    return pamret;
}

/* ============================================================================= */

/*
 * Close a session.  Normally, what we do here is call unlog, but we can be
 * configured not to do so.
 */

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
    const void*     dummy;
    int             pamret;
    int             already_afslog;
    kafs_handle_t*  kafs = NULL;

    putil_notice(pamh, ">>> pam_sm_close_session flags: %x",flags);

    /* Do nothing unless AFS is available. */
    if( ! k_hasafs() ) {
        putil_notice(pamh, "skipping, AFS apparently not available");
        pamret = PAM_IGNORE;
        goto done;
    }

    /* init user */
    kafs = __init_user(pamh);
    if( kafs == NULL ) {
        putil_err(pamh, "no suitable user");
        pamret = PAM_IGNORE;
        goto done;
    }

    /* shell we ignore user? */
    if( __ignore_user(kafs) == 1 ){
        pamret = PAM_SUCCESS;
        goto done;
    }

    /* was afslog already called? */
    already_afslog = 0;
    if( pam_get_data(pamh, PAMAFS_MODULE_NAME, &dummy) == PAM_SUCCESS ){
        already_afslog = 1;
    }

    if( (already_afslog == 0) || (_pamafs_shared_pag == 1) ){
        pamret = PAM_SUCCESS;   /* AFS tokens already destroyed or shared PAG */
        goto done;
    }

    /* become target user for subsequent operations */
    if( __enter_user(kafs) > 0 ){
        pamret = PAM_SESSION_ERR;
        goto done;
    }

    /* destroy all AFS tokens */
    int err = k_unlog();
    if( err != 0 ){
        putil_err(pamh, "unable to unlog");
        err = 1;
    }

    /* restore service user */
    if( __leave_user(kafs) ){
        pamret = PAM_SESSION_ERR;
        goto done;
    }

    /* remove module data */
    if( err == 0 ){
        if( pam_set_data(pamh, PAMAFS_MODULE_NAME, NULL, NULL) != PAM_SUCCESS ){
            putil_err(pamh, "unable to remove module data");
            pamret = PAM_SESSION_ERR;
            goto done;
        }
    }

    pamret = PAM_SUCCESS;

done:
    __free_user(kafs);
    putil_notice(pamh, "<<< pam_sm_close_session");
    return pamret;
}

/* ============================================================================= */
