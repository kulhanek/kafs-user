/* Copyright (c) 2021 Petr Kulhanek (kulhanek@chemi.muni.cz)
 * Support for kAFS (kernel AFS) adapted from Heimdal libkafs,
 * kafs-client and pam-afs-session.
 */
/*
 * Get or delete AFS tokens.
 *
 * Here are the functions to get or delete AFS tokens, called by the various
 * public functions.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2006, 2007, 2008, 2010, 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <syslog.h>
#include <security/pam_ext.h>

#include "internal.h"
#include <kafs-user.h>

/* ============================================================================= */

int conf_verbosity = 0;

/* ============================================================================= */

kafs_handle_t* __init_user(pam_handle_t *pamh)
{
    if (getuid() != geteuid() || getgid() != getegid()) {
        putil_err(pamh, "kafs setup in a setuid context ignored");
        return(NULL);
    }

    /* look up the target UID and GID */
    const char* username;

    int ret = pam_get_user(pamh, &username,NULL);
    if( ret != PAM_SUCCESS ){
        putil_err(pamh, "no username provided");
        return(NULL);
    }
    struct passwd* pw = getpwnam(username);
    if (!pw) {
        putil_err(pamh, "unable to look up user: '%s'",username);
        return(NULL);
    }

    kafs_handle_t* kafs = malloc(sizeof(kafs_handle_t));
    if( kafs == NULL ){
        putil_err(pamh, "unable to allocate kafs_handle_t");
        return(NULL);
    }

    kafs->pamh      = pamh;
    kafs->uid       = pw->pw_uid;
    kafs->old_uid   = getuid();
    kafs->old_euid  = geteuid();
    kafs->gid       = pw->pw_gid;
    kafs->old_gid   = getgid();

    /* config - default value */
    kafs->conf_min_uid    = 1000;
    kafs->conf_shared_pag = 0;

    /* read setup from krb5.conf */
    krb5_error_code kret;
    krb5_context    ctx;
    char*           p_cs;

    kret = krb5_init_context(&ctx);
    if( kret == 0 ){
        krb5_appdefault_boolean(ctx, PAMAFS_MODULE_NAME, NULL, "shared_pag", 0, &(kafs->conf_shared_pag));

        krb5_appdefault_string(ctx, PAMAFS_MODULE_NAME, NULL, "minimum_uid", "1000", &p_cs);
        kafs->conf_min_uid = atol(p_cs);

        krb5_free_context(ctx);
    } else {
        putil_err(pamh,"unable to init krb5 context for reading configuration - using defaults");
    }

    return(kafs);
}

/* ============================================================================= */

int __ignore_user(kafs_handle_t* kafs)
{
    if ((kafs->uid == 0) || (kafs->uid < kafs->conf_min_uid)) {
        putil_debug(kafs->pamh, "ignoring low-UID user (%u < %d)",kafs->uid, kafs->conf_min_uid);
        return(1);
    }
    return(0);
}

/* ============================================================================= */

int __enter_user(kafs_handle_t* kafs)
{
    putil_debug(kafs->pamh, ">>> __enter_user: uid:%u euid:%u gid:%u -> uid:%u gid:%u",
                 getuid(),geteuid(),getgid(),kafs->uid,-1);

    /* switch to the real and effective UID and GID so that the keyring ends up owned by the right user */
    if( (kafs->gid != kafs->old_gid) && (setregid(kafs->gid,-1) < 0) ) {
        putil_err(kafs->pamh, "__enter_user: unable to change GID to %u temporarily\n", kafs->gid);
        return(1);
    }

    if( (kafs->uid != kafs->old_uid) && (setreuid(kafs->uid,-1) < 0) ) {
        putil_err(kafs->pamh, "__enter_user: unable to change UID to %u temporarily\n", kafs->uid);
        if (setregid(kafs->old_gid,-1) < 0) {
            putil_err(kafs->pamh, "__enter_user: unable to change GID back to %u\n", kafs->old_gid);
        }
        return(2);
    }

    /* we need also to change effective UID for shared PAG and krb5 */

    if( (kafs->uid != kafs->old_euid) && (seteuid(kafs->uid) < 0) ) {
        putil_err(kafs->pamh, "__enter_user: unable to change EUID to %u temporarily\n", kafs->uid);
        if (setreuid(kafs->old_uid,-1) < 0) {
            putil_err(kafs->pamh, "__enter_user: unable to change UID back to %u\n", kafs->old_uid);
        }
        if (setregid(kafs->old_gid,-1) < 0) {
            putil_err(kafs->pamh, "__enter_user: unable to change GID back to %u\n", kafs->old_gid);
        }
        return(3);
    }

    putil_debug(kafs->pamh, "<<< __enter_user: uid:%u euid:%u gid:%u",
                 getuid(),geteuid(),getgid());

    return(0);
}

/* ============================================================================= */

int __leave_user(kafs_handle_t* kafs)
{
    putil_debug(kafs->pamh, ">>> __leave_user: uid:%u euid:%u gid:%u -> uid:%u gid:%u",
                 getuid(),geteuid(),getgid(),kafs->old_uid,kafs->old_gid);

    /* return to the original UID, EUID and GID (probably root) */

    int err = 0;
    if( (kafs->uid != kafs->old_euid) && (seteuid(kafs->old_euid) < 0) ) {
        putil_err(kafs->pamh,"__leave_user: unable to change EUID back to %d\n", kafs->old_euid);
        putil_err(kafs->pamh,"errno: %s",strerror(errno));
        err = 1;
    }

    /* return to the original UID and GID (probably root) */
    if( (kafs->uid != kafs->old_uid) && (setreuid(kafs->old_uid, -1) < 0) ) {
        putil_err(kafs->pamh,"__leave_user: unable to change UID back to %d\n", kafs->old_uid);
        putil_err(kafs->pamh,"errno: %s",strerror(errno));
        err = 2;
    }

    if( (kafs->gid != kafs->old_gid) && (setregid(kafs->old_gid, -1) < 0) ) {
        putil_err(kafs->pamh, "__leave_user: unable to change GID back to %d\n", kafs->old_gid);
        err = 3;
    }

    putil_debug(kafs->pamh, "<<< __leave_user: uid:%u euid:%u gid:%u",
                 getuid(),geteuid(),getgid());
    return(err);
}

/* ============================================================================= */

void __free_user(kafs_handle_t* kafs)
{
   if( kafs == NULL ) return;
   free(kafs);
}

/* ============================================================================= */

void putil_err(pam_handle_t* pamh,const char* p_fmt,...)
{
    /* for any verbocity */
    va_list vl;
    va_start(vl,p_fmt);
    pam_vsyslog(pamh,LOG_ERR,p_fmt,vl);
    va_end(vl);
}

/* ============================================================================= */

void putil_err_krb5(pam_handle_t* pamh,krb5_context ctx,int kerr,const char* p_fmt,...)
{
    va_list vl;
    va_start(vl,p_fmt);
    pam_vsyslog(pamh,LOG_ERR,p_fmt,vl);
    va_end(vl);

    const char* p_errm = krb5_get_error_message(ctx,kerr);
    if( p_errm ){
        putil_err(pamh, "krb5: %s\n",p_errm);
        krb5_free_error_message(ctx,p_errm);
    }
}

/* ============================================================================= */

void putil_debug(pam_handle_t* pamh,const char* p_fmt,...)
{
    if( conf_verbosity < 1 ) return;
    /* for verbosity one  and above */
    va_list vl;
    va_start(vl,p_fmt);
    pam_vsyslog(pamh,LOG_ERR,p_fmt,vl);
    va_end(vl);
}

/* ============================================================================= */

int pamkafs_afslog(pam_handle_t *pamh)
{    
    /* Don't try to get a token unless we have a K5 ticket cache. */
    const char* p_cc_name = pam_getenv(pamh, "KRB5CCNAME");
    if( p_cc_name == NULL ) p_cc_name = getenv("KRB5CCNAME");
    if( p_cc_name == NULL ) {
        putil_err(pamh,"no KRB5CCNAME");
        return(1);
    }

    /* init krb5 context and ccache */
    krb5_error_code kret;
    krb5_context    ctx;
    krb5_ccache     ccache;

    kret = krb5_init_context(&ctx);
    if( kret != 0 ){
        putil_err(pamh,"unable to init krb5 context");
        return(2);
    }

    kret = krb5_cc_resolve(ctx, p_cc_name, &ccache);
    if( kret != 0 ) {
        putil_err_krb5(pamh,ctx,kret,"unable to resolve ccache");
        krb5_free_context(ctx);
        return(3);
    }

    /* afslog */
    kret = krb5_afslog(ctx, ccache, NULL, NULL);

    /* clean up */
    krb5_cc_close(ctx, ccache);
    krb5_free_context(ctx);

    if( kret != 0 ) {
        putil_err(pamh,"krb5_afslog failed");
        return(4);
    }
    return(0);
}

/* ============================================================================= */
