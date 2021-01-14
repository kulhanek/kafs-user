/* Copyright (c) 2021 Petr Kulhanek (kulhanek@chemi.muni.cz)
 * Support for kAFS (kernel AFS) adapted from Heimdal libkafs,
 * kafs-client and pam-afs-session.
 */
/*
 * Copyright (c) 1995, 1996, 1997, 1998, 1999 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/* aklog.c: description
 *
 * Copyright (C) 2017 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * Based on code:
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 * Copyright (C) 2008 Chaskiel Grundman. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Kerberos-5 strong enctype support for rxkad:
 *      https://tools.ietf.org/html/draft-kaduk-afs3-rxkad-k5-kdf-00
 *
 * Invoke as: aklog-k5 <cell> [<realm>]
 */

#ifndef __KAFS_LOCL_H__
#define __KAFS_LOCL_H__

#include <keyutils.h>

/* ============================================================================= */

struct rxrpc_key_sec2_v1 {
        uint32_t        kver;                   /* key payload interface version */
        uint16_t        security_index;         /* RxRPC header security index */
        uint16_t        ticket_length;          /* length of ticket[] */
        uint32_t        expiry;                 /* time at which expires */
        uint32_t        kvno;                   /* key version number */
        uint8_t         session_key[8];         /* DES session key */
        uint8_t         ticket[];               /* the encrypted ticket as felxible array */
};

#define RXKAD_TKT_TYPE_KERBEROS_V5              256

/* ============================================================================= */

/* Default to a hidden visibility for all internal functions. */
#pragma GCC visibility push(hidden)

/* ============================================================================= */

/*
 * 0 - no debug
 * 1 - debug to stderr
 * 2 - debgu to the /tmp/kafs file
 */

extern int _kafs_debug;

/* ============================================================================= */

/* print debug info */
void _kafs_vdbg(const char* p_fmt,va_list vl);
void _kafs_dbg(const char* p_fmt,...)       __attribute__((__format__(printf, 1, 2)));
void _kafs_dbg_errno(const char* p_fmt,...) __attribute__((__format__(printf, 1, 2)));
void _kafs_dbg_krb5(krb5_context ctx,int kerr,const char* p_fmt,...)
                                            __attribute__((__format__(printf, 3, 4)));

/* ============================================================================= */

/* create AFS token, cell MUST be provided, REALM is determined from krb5.conf */
krb5_error_code _kafs_set_afs_token_1(krb5_context ctx,
                 krb5_ccache ccache,
                 const char* cell);

/* create AFS token, cell and realm MUST be provided */
krb5_error_code _kafs_set_afs_token_2(krb5_context ctx,
                 krb5_ccache id,
                 const char* cell,
                 const char* realm);

/* get AFS service ticket */
int _kafs_get_creds(krb5_context ctx,
                   krb5_ccache ccache,
                   const char* cell,
                   const char* realm,
                   krb5_creds** creds);

/* insert token into session keyring */
int _kafs_settoken_rxkad(const char* cell, krb5_creds* creds);

/* derive session key */
int _kafs_derive_des_key(krb5_enctype enctype, void *keydata, size_t keylen,
                         unsigned char output[8]);

/* invalidate AFS token for k_unlog() */
int _kafs_invalidate_key(key_serial_t parent,key_serial_t key, char *desc, int desc_len, void *data);

/* list AFS tokens for k_list_tokens() */
int _kafs_list_key(key_serial_t parent,key_serial_t key, char *desc, int desc_len, void *data);

/* ============================================================================= */

/* Undo default visibility change. */
#pragma GCC visibility pop

/* ============================================================================= */

#endif /* __KAFS_LOCL_H__ */
