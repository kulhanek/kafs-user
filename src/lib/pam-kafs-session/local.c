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

#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <syslog.h>
#include <fnmatch.h>
#include <stdio.h>
#include <linux/limits.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include "internal.h"
#include <kafs-user.h>

/* ============================================================================= */

kafs_handle_t* __init_user(pam_handle_t *pamh)
{
    kafs_handle_t* kafs = malloc(sizeof(kafs_handle_t));
    if( kafs == NULL ){
        pam_syslog(pamh,LOG_ERR,"unable to allocate kafs_handle_t");
        return(NULL);
    }

    kafs->pamh      = pamh;
    kafs->ctx       = NULL;

    /* config - default value */
    kafs->conf_verbosity                = 0;
    kafs->conf_create_pag               = 1;
    kafs->conf_create_tokens            = 1;
    kafs->conf_minimum_uid              = 1000;
    kafs->conf_shared_pag               = 0;
    kafs->conf_locpag_for_pam           = NULL;
    kafs->conf_locpag_for_user          = NULL;
    kafs->conf_locpag_for_principal     = NULL;
    kafs->conf_convert_cc_to_kcm        = 0;

    /* read setup from krb5.conf */
    krb5_error_code kret;
    char*           p_cs;

    kret = krb5_init_context(&(kafs->ctx));
    if( kret != 0 ){
        putil_err(kafs,"unable to init krb5 context");
        goto err;
    }

    krb5_appdefault_string(kafs->ctx, PAMAFS_MODULE_NAME, NULL, "verbosity", "0", &p_cs);
    kafs->conf_verbosity = atol(p_cs);

    krb5_appdefault_boolean(kafs->ctx, PAMAFS_MODULE_NAME, NULL, "create_pag", 1, &(kafs->conf_create_pag));
    krb5_appdefault_boolean(kafs->ctx, PAMAFS_MODULE_NAME, NULL, "create_tokens", 1, &(kafs->conf_create_tokens));

    krb5_appdefault_boolean(kafs->ctx, PAMAFS_MODULE_NAME, NULL, "shared_pag", 0, &(kafs->conf_shared_pag));

    krb5_appdefault_string(kafs->ctx, PAMAFS_MODULE_NAME, NULL, "minimum_uid", "1000", &p_cs);
    kafs->conf_minimum_uid = atol(p_cs);

    krb5_appdefault_string(kafs->ctx, PAMAFS_MODULE_NAME, NULL, "locpag_for_pam", NULL, &(kafs->conf_locpag_for_pam));
    krb5_appdefault_string(kafs->ctx, PAMAFS_MODULE_NAME, NULL, "locpag_for_user", NULL, &(kafs->conf_locpag_for_user));
    krb5_appdefault_string(kafs->ctx, PAMAFS_MODULE_NAME, NULL, "locpag_for_principal", NULL, &(kafs->conf_locpag_for_principal));

    krb5_appdefault_boolean(kafs->ctx, PAMAFS_MODULE_NAME, NULL, "convert_cc_to_kcm", 0, &(kafs->conf_convert_cc_to_kcm));

/* check the user context */
    if (getuid() != geteuid() || getgid() != getegid()) {
        putil_err(kafs, "kafs setup in a setuid context ignored");
        goto err;
    }

    /* look up the target UID and GID */
    const char* username;

    int ret = pam_get_user(pamh, &username,NULL);
    if( ret != PAM_SUCCESS ){
        putil_err(kafs, "no username provided");
        goto err;
    }
    struct passwd* pw = pam_modutil_getpwnam(kafs->pamh,username);
    if (!pw) {
        putil_err(kafs, "unable to look up user: '%s'",username);
        goto err;
    }

    kafs->pw_name   = pw->pw_name;
    kafs->uid       = pw->pw_uid;
    kafs->old_uid   = getuid();
    kafs->old_euid  = geteuid();
    kafs->gid       = pw->pw_gid;
    kafs->old_gid   = getgid();

    if( kafs->conf_verbosity == 2 ){
        /* some internal information */
        char** p_s = environ;
        char** p_i = p_s;
        while( *p_i ){
            putil_debug(kafs,"> SYSENV: %s",*p_i);
            p_i++;
        }

        p_s = pam_getenvlist(pamh);
        if( p_s ){
            char** p_i = p_s;
            while( *p_i ){
                putil_debug(kafs,"> PAMENV: %s",*p_i);
                p_i++;
            }
            free(p_s);
        }

        const void* p_tty;
        ret = pam_get_item(kafs->pamh, PAM_TTY, &p_tty);
        putil_debug(kafs,"> TTY: %s",(char*)p_tty);
    }

    return(kafs);

err:
    if( kafs->ctx ) krb5_free_context(kafs->ctx);
    if( kafs ) free(kafs);
    return(NULL);
}

/* ============================================================================= */

void __free_user(kafs_handle_t* kafs)
{
   if( kafs == NULL ) return;
   krb5_free_context(kafs->ctx);
   free(kafs);
}

/* ============================================================================= */

int __ignore_user(kafs_handle_t* kafs)
{
    if ((kafs->uid == 0) || (kafs->uid < kafs->conf_minimum_uid)) {
        putil_debug(kafs, "ignoring low-UID user (%u < %d)",kafs->uid, kafs->conf_minimum_uid);
        return(1);
    }

    return(0);
}

/* ============================================================================= */

int __enter_user(kafs_handle_t* kafs)
{
    putil_debug(kafs, "__enter_user: uid:%u euid:%u gid:%u",
                 getuid(),geteuid(),getgid());

    /* switch to the real and effective UID and GID so that the keyring ends up owned by the right user */
    if( (kafs->gid != kafs->old_gid) && (setregid(kafs->gid,-1) < 0) ) {
        putil_errno(kafs, "  unable to change GID to %u temporarily", kafs->gid);
        return(1);
    }

    if( (kafs->uid != kafs->old_uid) && (setreuid(kafs->uid,-1) < 0) ) {
        putil_errno(kafs, "  unable to change UID to %u temporarily", kafs->uid);
        if (setregid(kafs->old_gid,-1) < 0) {
            putil_errno(kafs, "  unable to change GID back to %u", kafs->old_gid);
        }
        return(2);
    }

    /* we need also to change effective UID for shared PAG and krb5 */

    if( (kafs->uid != kafs->old_euid) && (seteuid(kafs->uid) < 0) ) {
        putil_errno(kafs, "  unable to change EUID to %u temporarily", kafs->uid);
        if (setreuid(kafs->old_uid,-1) < 0) {
            putil_errno(kafs, "  unable to change UID back to %u", kafs->old_uid);
        }
        if (setregid(kafs->old_gid,-1) < 0) {
            putil_errno(kafs, "  unable to change GID back to %u", kafs->old_gid);
        }
        return(3);
    }

    putil_debug(kafs, "  target: uid:%u euid:%u gid:%u",
                getuid(),geteuid(),getgid());

    return(0);
}

/* ============================================================================= */

int __leave_user(kafs_handle_t* kafs)
{
    putil_debug(kafs, "__leave_user: uid:%u euid:%u gid:%u",
                 getuid(),geteuid(),getgid());

    /* return to the original UID, EUID and GID (probably root) */

    int err = 0;
    if( (kafs->uid != kafs->old_euid) && (seteuid(kafs->old_euid) < 0) ) {
        putil_errno(kafs,"  unable to change EUID back to %d\n", kafs->old_euid);
        err = 1;
    }

    /* return to the original UID and GID (probably root) */
    if( (kafs->uid != kafs->old_uid) && (setreuid(kafs->old_uid, -1) < 0) ) {
        putil_errno(kafs,"  unable to change UID back to %d\n", kafs->old_uid);
        err = 2;
    }

    if( (kafs->gid != kafs->old_gid) && (setregid(kafs->old_gid, -1) < 0) ) {
        putil_errno(kafs, "  unable to change GID back to %d\n", kafs->old_gid);
        err = 3;
    }

    putil_debug(kafs, "  target: uid:%u euid:%u gid:%u",
                 getuid(),geteuid(),getgid());
    return(err);
}

/* ============================================================================= */

void putil_err(kafs_handle_t* kafs,const char* p_fmt,...)
{
    if( kafs == NULL ) return;

    /* for any verbocity */
    va_list vl;
    va_start(vl,p_fmt);
    pam_vsyslog(kafs->pamh,LOG_ERR,p_fmt,vl);
    va_end(vl);
}

/* ============================================================================= */

void putil_errno(kafs_handle_t* kafs,const char* p_fmt,...)
{
    if( kafs == NULL ) return;

    int lerrno = errno;
    /* for any verbocity */
    va_list vl;
    va_start(vl,p_fmt);
    pam_vsyslog(kafs->pamh,LOG_ERR,p_fmt,vl);
    va_end(vl);
    putil_err(kafs,"errno: %d (%s)",lerrno,strerror(lerrno));
}

/* ============================================================================= */

void putil_err_krb5(kafs_handle_t* kafs,int kerr,const char* p_fmt,...)
{
    if( kafs == NULL ) return;

    va_list vl;
    va_start(vl,p_fmt);
    pam_vsyslog(kafs->pamh,LOG_ERR,p_fmt,vl);
    va_end(vl);

    const char* p_errm = krb5_get_error_message(kafs->ctx,kerr);
    if( p_errm ){
        putil_err(kafs, "krb5: %s\n",p_errm);
        krb5_free_error_message(kafs->ctx,p_errm);
    }
}

/* ============================================================================= */

void putil_notice(kafs_handle_t* kafs,const char* p_fmt,...)
{
    if( kafs == NULL ) return;

    /* verbosity == 1 and above */
    if( kafs->conf_verbosity < 1 ) return;
    va_list vl;
    va_start(vl,p_fmt);
    pam_vsyslog(kafs->pamh,LOG_ERR,p_fmt,vl);
    va_end(vl);
}

/* ============================================================================= */

void putil_debug(kafs_handle_t* kafs,const char* p_fmt,...)
{
    if( kafs == NULL ) return;

    /* verbosity == 1 and above */
    if( kafs->conf_verbosity < 2 ) return;

    va_list vl;
    va_start(vl,p_fmt);
    pam_vsyslog(kafs->pamh,LOG_ERR,p_fmt,vl);
    va_end(vl);
}

/* ============================================================================= */

int pamkafs_create(kafs_handle_t* kafs,int redo)
{
    const void*     dummy;
    int             already_afslog;

    /* was afslog already called? */
    already_afslog = 0;
    if( pam_get_data(kafs->pamh, PAMAFS_MODULE_NAME AFSLOG, &dummy) == PAM_SUCCESS ){
        already_afslog = 1;
    }

    /* become target user for subsequent operations */
    if( __enter_user(kafs) > 0 ){
        return(1);
    }

    int err = 0;

    /* do some tests within context of target user */
    if( pamkafs_tests_for_locpag(kafs) != 0 ){
        err = 1;
    }

    if( (kafs->conf_create_pag == 1) && (err == 0) ) {
        /* create PAG if necessary
         */
        if( k_haspag() == 0 ){
            if( kafs->conf_shared_pag == 1 ) {
                if( k_setpag_shared() != 0 ){
                    putil_err(kafs, "unable to create shared PAG");
                    err = 2;
                } else {
                    putil_debug(kafs,"shared PAG created");
                }
            } else {
                if( k_setpag() != 0 ){
                    putil_err(kafs, "unable to create PAG");
                    err = 2;
                } else {
                    putil_debug(kafs,"local PAG created");
                }
            }
            if( err == 0 ) already_afslog = 0; /* PAG created - we need to afslog */
        }
    }

    if( pamkafs_convert_to_kcm(kafs) != 0 ){
        err = 3;
    }

    /* recreate tokens as requested */
    if( redo ){
        already_afslog = 0;
    }

    /* afslog */
    if( (kafs->conf_create_tokens == 1) && (already_afslog == 0) && (err == 0) ) {
        if( pamkafs_afslog(kafs) != 0 ) {
            putil_err(kafs, "unable to afslog");
            err = 4;
        }else {
            putil_debug(kafs,"AFS tokens created");
        }
    }

    /* restore service user */
    if( __leave_user(kafs) ){
        return(2);
    }

    /* record success */
    if( (already_afslog == 0) && (err == 0 ) ){
        if( pam_set_data(kafs->pamh, PAMAFS_MODULE_NAME AFSLOG, (char *) "yes", NULL) != PAM_SUCCESS ){
            putil_err(kafs, "cannot set success data - afslog");
            return(3);
        }
    }

    if( err != 0 ) return(4);
    return(0);
}

/* ============================================================================= */

int pamkafs_tests_for_locpag(kafs_handle_t* kafs)
{
    const void*     dummy;

    if( pam_get_data(kafs->pamh, PAMAFS_MODULE_NAME LOCPAG, &dummy) == PAM_SUCCESS ){
        /* disable shared PAG due to matching principal */
        kafs->conf_shared_pag = 0;
    }

    if( pam_get_data(kafs->pamh, PAMAFS_MODULE_NAME AFSLOG, &dummy) == PAM_SUCCESS ){
        /* already run */
        return(0);
    }

    int use_local_pag = 0;

/* check by PAM service name if configured */
    if( (kafs->conf_locpag_for_pam != NULL) && (kafs->conf_shared_pag == 1) ){
        putil_debug(kafs,"> filter by PAM service: %s",kafs->conf_locpag_for_pam);

        const void* p_service;
        int ret = pam_get_item(kafs->pamh, PAM_SERVICE, &p_service);
        if( ret != PAM_SUCCESS ){
            putil_err(kafs, "no PAM service name");
            return(1);
        }
        if( fnmatch(kafs->conf_locpag_for_pam,p_service,FNM_EXTMATCH) == 0 ){
            putil_notice(kafs, "local PAG only for PAM service '%s' as requested",(char*)p_service);
            use_local_pag = 1;
        }
    }

/* check by target user name if configured */
    if( (kafs->conf_locpag_for_user != NULL) && (kafs->conf_shared_pag == 1) ){
        putil_debug(kafs,"> filter by target user name: %s",kafs->conf_locpag_for_user);

        if( kafs->pw_name != NULL ){
            putil_debug(kafs, "> target user name '%s'",kafs->pw_name);
            if( fnmatch(kafs->conf_locpag_for_user,kafs->pw_name,FNM_EXTMATCH) == 0 ){
                putil_notice(kafs, "local PAG only for target user name '%s' as requested",(char*)kafs->pw_name);
                use_local_pag = 1;
            }
        }
    }

/* check by ccache principal name if configured */
    if( (kafs->conf_locpag_for_principal != NULL) && (kafs->conf_shared_pag == 1) ){
        putil_debug(kafs,"> filter by principal: %s",kafs->conf_locpag_for_principal);

        /* we need K5 ticket cache. */
        const char* p_cc_name = pam_getenv(kafs->pamh, "KRB5CCNAME");
        if( p_cc_name == NULL ) p_cc_name = getenv("KRB5CCNAME");
        if( p_cc_name != NULL ) {
            krb5_error_code kret;
            krb5_ccache     ccache;
            krb5_principal  princ;

            kret = krb5_cc_resolve(kafs->ctx, p_cc_name, &ccache);
            if( kret != 0 ) {
                putil_err_krb5(kafs,kret,"unable to resolve ccache");
                return(2);
            }

            kret = krb5_cc_get_principal(kafs->ctx,ccache,&princ);
            if( kret != 0 ) {
                putil_err_krb5(kafs,kret,"unable to get default principal");
                return(3);
            }

            char* p_sname;
            if( krb5_unparse_name(kafs->ctx, princ, &p_sname) != 0 ){
                putil_err_krb5(kafs,kret,"unable to get principal name");
                return(4);
            }

            putil_debug(kafs, "> default ccache principal '%s'",p_sname);
            if( fnmatch(kafs->conf_locpag_for_principal,p_sname,FNM_EXTMATCH) == 0 ){
                putil_notice(kafs, "local PAG only for default ccache principal '%s' as requested",p_sname);
                use_local_pag = 1;
            }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
            krb5_free_unparsed_name(kafs->ctx,p_sname);
#pragma GCC diagnostic pop

            krb5_free_principal(kafs->ctx,princ);
            krb5_cc_close(kafs->ctx, ccache);
        }
    }

    if( use_local_pag == 1 ){
        kafs->conf_shared_pag = 0;
        if( pam_set_data(kafs->pamh, PAMAFS_MODULE_NAME LOCPAG, (char *) "yes", NULL) != PAM_SUCCESS ){
            putil_err(kafs, "cannot set success data - locpag");
            return(5);
        }
    }

    return(0);
}

/* ============================================================================= */

int pamkafs_convert_to_kcm(kafs_handle_t* kafs)
{
    if( kafs->conf_convert_cc_to_kcm == 0 ) return(0);

    putil_debug(kafs,"> converting ccache type to KCM");

    const char* p_cc_name = pam_getenv(kafs->pamh, "KRB5CCNAME");
    if( p_cc_name == NULL ) p_cc_name = getenv("KRB5CCNAME");
    if( p_cc_name == NULL ) {
        putil_debug(kafs,"no KRB5CCNAME");
        return(0);
    }

    krb5_error_code kret;
    krb5_ccache     ccache;

    kret = krb5_cc_resolve(kafs->ctx, p_cc_name, &ccache);
    if( kret != 0 ) {
        putil_err_krb5(kafs,kret,"unable to resolve ccache");
        return(1);
    }

    const char* p_cctype = krb5_cc_get_type(kafs->ctx,ccache);
    if( strstr(p_cctype,"KCM") != p_cctype ){
        putil_notice(kafs,"converting ccache type (%s) to KCM as requested",p_cctype);

        krb5_ccache     ccache2;
        char            buffer[PATH_MAX];

        snprintf(buffer,sizeof(buffer),"KCM:%d",kafs->uid);

        kret = krb5_cc_resolve(kafs->ctx,buffer,&ccache2);
        if( kret != 0 ) {
            putil_err_krb5(kafs,kret,"unable to resolve KCM cache '%s",buffer);
            krb5_cc_close(kafs->ctx, ccache);
            return(2);
        }

        kret = krb5_cc_copy_cache(kafs->ctx, ccache, ccache2);
        if( kret != 0 ) {
            putil_err_krb5(kafs,kret,"unable to duplicate ccache");
            krb5_cc_close(kafs->ctx, ccache);
            return(3);
        }

        krb5_cc_close(kafs->ctx, ccache2);

        /* destroy previous ccache */
        krb5_cc_destroy(kafs->ctx, ccache);

        /* set KRB5CCNAME */
        if( setenv("KRB5CCNAME",buffer,1) != 0 ){
            putil_errno(kafs,"unable to setenv with SYS KRB5CCNAME='%s'",buffer);
            return(4);
        }

        snprintf(buffer,sizeof(buffer),"KRB5CCNAME=KCM:%d",kafs->uid);
        if( pam_putenv(kafs->pamh,buffer) != PAM_SUCCESS ){
            putil_errno(kafs,"unable to setenv with PAM %s",buffer);
            return(4);
        }

        putil_debug(kafs,"new ccache: %s",buffer);

    } else {
        putil_debug(kafs,"ccache type is already KCM");
        krb5_cc_close(kafs->ctx, ccache);
    }

    return(0);
}

/* ============================================================================= */

int pamkafs_afslog(kafs_handle_t* kafs)
{    
    /* Don't try to get a token unless we have a K5 ticket cache. */
    const char* p_cc_name = pam_getenv(kafs->pamh, "KRB5CCNAME");
    if( p_cc_name == NULL ) p_cc_name = getenv("KRB5CCNAME");
    if( p_cc_name == NULL ) {
        putil_err(kafs,"no KRB5CCNAME");
        return(1);
    }

    /* init krb5 ccache */
    krb5_error_code kret;
    krb5_ccache     ccache;

    kret = krb5_cc_resolve(kafs->ctx, p_cc_name, &ccache);
    if( kret != 0 ) {
        putil_err_krb5(kafs,kret,"unable to resolve ccache");
        return(3);
    }

    /* afslog */
    kret = krb5_afslog(kafs->ctx, ccache, NULL, NULL);

    /* clean up */
    krb5_cc_close(kafs->ctx, ccache);

    if( kret != 0 ) {
        putil_err(kafs,"krb5_afslog failed");
        return(4);
    }
    return(0);
}

/* ============================================================================= */

int pamkafs_destroy(kafs_handle_t* kafs)
{
    const void*     dummy;
    int             already_afslog;

    /* was afslog already called? */
    already_afslog = 0;
    if( pam_get_data(kafs->pamh, PAMAFS_MODULE_NAME AFSLOG, &dummy) == PAM_SUCCESS ){
        already_afslog = 1;
    }

    if( pam_get_data(kafs->pamh, PAMAFS_MODULE_NAME LOCPAG, &dummy) == PAM_SUCCESS ){
        /* disable shared PAG due to matching principal */
        kafs->conf_shared_pag = 0;
    }

    if( (already_afslog == 0) || (kafs->conf_shared_pag == 1) || (kafs->conf_create_tokens == 0) ){
        return(0); /* AFS tokens already destroyed or shared PAG or create_tokens is off*/
    }

    /* become target user for subsequent operations */
    if( __enter_user(kafs) > 0 ){
        return(1);
    }

    /* destroy all AFS tokens */
    int err = k_unlog();
    if( err != 0 ){
        putil_err(kafs, "unable to unlog");
        err = 1;
    }else {
        putil_debug(kafs,"AFS tokens destroyed");
    }

    /* restore service user */
    if( __leave_user(kafs) ){
        return(2);
    }

    /* remove module data */
    if( err == 0 ){
        if( pam_set_data(kafs->pamh, PAMAFS_MODULE_NAME AFSLOG, NULL, NULL) != PAM_SUCCESS ){
            putil_err(kafs, "unable to remove module data");
            return(3);
        }
    }

    if( err != 0 ) return(4);
    return(0);
}

/* ============================================================================= */
