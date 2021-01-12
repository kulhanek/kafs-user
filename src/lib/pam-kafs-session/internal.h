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
    uid_t           old_uid,uid;
    gid_t           old_gid,gid;
};

typedef struct pma_kafs_handle kafs_handle_t;

/* ============================================================================= */

/* logging */
void putil_err(pam_handle_t* pamh,const char* p_fmt,...)
                __attribute__((__format__(printf, 2, 3)));

void putil_notice(pam_handle_t* pamh,const char* p_fmt,...)
                __attribute__((__format__(printf, 2, 3)));

void putil_err_krb5(pam_handle_t* pamh,krb5_context ctx,int kerr,const char* p_fmt,...)
                __attribute__((__format__(printf, 4, 5)));

/* ============================================================================= */

/* user magic */
kafs_handle_t* __init_user(pam_handle_t *pamh);
int  __ignore_user(kafs_handle_t* kafs);
int  __enter_user(kafs_handle_t* kafs);
int  __leave_user(kafs_handle_t* kafs);
void __free_user(kafs_handle_t* kafs);

/* ============================================================================= */

/* afslog */
int pamkafs_afslog(pam_handle_t *pamh);

/* ============================================================================= */

/* Hardcoded pam_kafs_session configurations */
extern int _pamafs_min_uid;
extern int _pamafs_shared_pag;
extern int _pamefs_verbosity;

#define PAMAFS_MODULE_NAME          "pam_kafs_session"

/* ============================================================================= */

/* Undo default visibility change. */
#pragma GCC visibility pop

#endif /* INTERNAL_H */
