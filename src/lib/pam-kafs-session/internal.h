/* Copyright (c) 2021 Petr Kulhanek (kulhanek@chemi.muni.cz)
 * Support for kAFS (kernel AFS) adapted from Heimdal libkafs,
 * kafs-client and pam-afs-session.
 */
/*
 * Internal prototypes and structures for pam-afs-session.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2006, 2007, 2008, 2010, 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#ifndef INTERNAL_H
#define INTERNAL_H 1

#include <stdbool.h>
#include <security/pam_modules.h>
#include <krb5.h>
#include <unistd.h>
#include <sys/types.h>

/* ============================================================================= */

/* Used for unused parameters to silence gcc warnings. */
#define UNUSED  __attribute__((__unused__))

/* Default to a hidden visibility for all internal functions. */
#pragma GCC visibility push(hidden)

/* ============================================================================= */

struct pma_kafs_handle {
    pam_handle_t*   pamh;
    krb5_context    ctx;

    char*           pw_name;
    uid_t           old_uid,old_euid,uid;
    gid_t           old_gid,old_egid,gid;

    /* local config */
    int     conf_verbosity;
    int     conf_create_pag;
    int     conf_create_tokens;
    int     conf_minimum_uid;
    int     conf_shared_pag;
    char*   conf_locpag_for_pam;
    char*   conf_locpag_for_user;
    char*   conf_locpag_for_principal;
    char*   conf_convert_cc_to;
};

typedef struct pma_kafs_handle kafs_handle_t;

/* ============================================================================= */

/* logging */
void putil_err(kafs_handle_t* kafs,const char* p_fmt,...)
                __attribute__((__format__(printf, 2, 3)));

void putil_errno(kafs_handle_t* kafs,const char* p_fmt,...)
                __attribute__((__format__(printf, 2, 3)));

void putil_notice(kafs_handle_t* kafs,const char* p_fmt,...)
                __attribute__((__format__(printf, 2, 3)));

void putil_debug(kafs_handle_t* kafs,const char* p_fmt,...)
                __attribute__((__format__(printf, 2, 3)));

void putil_err_krb5(kafs_handle_t* kafs,int kerr,const char* p_fmt,...)
                __attribute__((__format__(printf, 3, 4)));

/* ============================================================================= */

/* user magic */
kafs_handle_t* __init_user(pam_handle_t *pamh);
int  __ignore_user(kafs_handle_t* kafs);
int  __enter_user(kafs_handle_t* kafs);
int  __leave_user(kafs_handle_t* kafs);
void __free_user(kafs_handle_t* kafs);

/* ============================================================================= */

/* create PAG and tokens */
int pamkafs_create(kafs_handle_t* kafs, int redo, int session);

/* test if local PAG shoudl be created instead of shared one */
int pamkafs_tests_for_locpag(kafs_handle_t* kafs);

/* if requested, convert ccache type to desired type - only in session */
int pamkafs_convert_ccache(kafs_handle_t* kafs);

/* afslog */
int pamkafs_afslog(kafs_handle_t* kafs);

/* destroy tokens */
int pamkafs_destroy(kafs_handle_t* kafs);

/* ============================================================================= */

/* module name for PAM and krb5.conf */
#define PAMAFS_MODULE_NAME          "pam-kafs-session"
#define AFSLOG                      "-afslog"
#define LOCPAG                      "-locpag"

/* ============================================================================= */

/* Undo default visibility change. */
#pragma GCC visibility pop

#endif /* INTERNAL_H */
