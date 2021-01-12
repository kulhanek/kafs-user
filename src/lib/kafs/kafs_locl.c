/* Copyright (c) 2021 Petr Kulhanek (kulhanek@chemi.muni.cz)
 * Support for kAFS (kernel AFS) adapted from Heimdal libkafs,
 * kafs-client and pam-afs-session.
 */
/*
 * Copyright (c) 1995 - 2001, 2003 Kungliga Tekniska Högskolan
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

#define _GNU_SOURCE
#include <stdio.h>
#include <krb5.h>
#include <keyutils.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/limits.h>
#include <string.h>
#include <stdlib.h>

#include <kafs-user.h>
#include <kafs_locl.h>

/* ============================================================================= */

int _kafs_debug = 0;

/* ============================================================================= */

void _kafs_dbg_errno(const char* p_fmt,...)
{
    va_list vl;
    va_start(vl,p_fmt);
    _kafs_vdbg(p_fmt,vl);
    va_end(vl);

    _kafs_dbg("errno: %d (%s)\n",errno,strerror(errno));
}

/* ------------------------ */

void _kafs_dbg_krb5(krb5_context ctx,int kerr,const char* p_fmt,...)
{
    va_list vl;
    va_start(vl,p_fmt);
    _kafs_vdbg(p_fmt,vl);
    va_end(vl);

    const char* p_errm = krb5_get_error_message(ctx,kerr);
    if( p_errm ){
        _kafs_dbg("krb5: %s\n",p_errm);
        krb5_free_error_message(ctx,p_errm);
    }
}

/* ------------------------ */

void _kafs_dbg(const char* p_fmt,...)
{
    va_list vl;
    va_start(vl,p_fmt);
    _kafs_vdbg(p_fmt,vl);
    va_end(vl);
}

/* ------------------------ */

void _kafs_vdbg(const char* p_fmt,va_list vl)
{
    if( _kafs_debug == 0 ) return;

    FILE* p_fo = stderr;
    if( _kafs_debug == 2 ){
        p_fo = fopen(_KAFS_DEBUG_FILE,"a");
        if( p_fo == NULL ) return;
    }

    vfprintf(p_fo,p_fmt,vl);

    if( _kafs_debug == 2  ) fclose(p_fo);
}

/* ============================================================================= */

krb5_error_code _kafs_set_afs_token_1(krb5_context ctx,
                 krb5_ccache id,
                 const char* cell)
{
    _kafs_dbg("-> _kafs_set_afs_token_1\n");

    krb5_realm*     realms;
    krb5_error_code kerr;

    kerr = krb5_get_host_realm(ctx, cell, &realms);
    if( kerr != 0 ) {
        _kafs_dbg_krb5(ctx,kerr,"unable to get realm for the host: '%s'\n",cell);
        return(kerr);
    }

    if( realms[0] != NULL ){
        kerr = _kafs_set_afs_token_2(ctx,id,cell,realms[0]);
    }  else {
        _kafs_dbg("not know realm for the host '%s'\n",cell);
        kerr = -1;
    }

    krb5_free_host_realm(ctx, realms);

    return(kerr);
}

/* ============================================================================= */

krb5_error_code _kafs_set_afs_token_2(krb5_context ctx,
                 krb5_ccache ccache,
                 const char* cell,
                 krb5_const_realm realm)
{
    _kafs_dbg("-> _kafs_set_afs_token_2\n");

    krb5_creds*         creds;
    int                 ret;
    krb5_error_code     kerr;

    kerr = _kafs_get_creds(ctx,ccache,cell,realm,&creds);
    if( kerr != 0 ){
        _kafs_dbg("kafs_get_creds failed\n");
        return(kerr);
    }
    ret = _kafs_settoken_rxkad(cell,creds);

    krb5_free_creds(ctx,creds);

    if( ret == -1 ){
        _kafs_dbg("kafs_settoken_rxkad failed\n");
        return(-1);
    }
    return(0);
}

/* ============================================================================= */

int _kafs_get_creds(krb5_context ctx,
                   krb5_ccache ccache,
                   const char* cell,
                   krb5_const_realm realm,
                   krb5_creds** creds)
{
    _kafs_dbg("-> _kafs_get_creds\n");

    krb5_creds search_cred;
    memset(&search_cred, 0, sizeof(krb5_creds));

    krb5_error_code kerr;
    kerr = krb5_cc_get_principal(ctx, ccache, &(search_cred.client));
    if( kerr != 0 ){
        _kafs_dbg_krb5(ctx,kerr,"unable to get principal from ccache\n");
        return(kerr);
    }

    char*   princ;
    int     ret;

    ret = asprintf(&princ, "afs/%s@%s", cell, realm);
    if( ret == -1 ) {
        krb5_free_principal(ctx,search_cred.client);
        errno = ENOMEM;
        _kafs_dbg("unable to create afs service principal name (cell: %s, realm: %s)\n",cell,realm);
        return(-1);
    }

    _kafs_dbg("(cell: %s, realm: %s, princ: %s)\n",cell,realm,princ);

    kerr = krb5_parse_name(ctx, princ, &search_cred.server);
    if( kerr != 0 ) {
        _kafs_dbg_krb5(ctx,kerr,"unable to parse afs service principal name\n");
        krb5_free_principal(ctx,search_cred.client);
        free(princ);
        return(kerr);
    }

    kerr = krb5_get_credentials(ctx, 0, ccache, &search_cred, creds);

    free(princ);
    krb5_free_principal(ctx,search_cred.client);
    krb5_free_principal(ctx,search_cred.server);

    if( kerr != 0 ) {
        _kafs_dbg_krb5(ctx,kerr,"unable to get credentials for afs service principal\n");
        return(kerr);
    }
    return(0);
}

/* ============================================================================= */

int _kafs_settoken_rxkad(const char* cell, krb5_creds* creds)
{
    _kafs_dbg("-> _kafs_settoken_rxkad\n");

    char*   keydesc;
    int     ret;

    ret = asprintf(&keydesc, "afs@%s", cell);
    if( ret == -1 ) {
        errno = ENOMEM;
        _kafs_dbg_errno("unable to create key description for cell '%s'\n",cell);
        return(-1);
    }

    struct rxrpc_key_sec2_v1*   payload;
    size_t                      plen;

    plen = sizeof(*payload) + creds->ticket.length;
    payload = calloc(1, plen + 4);
    if( payload == NULL ) {
        errno = ENOMEM;
        _kafs_dbg_errno("unable to allocate kt payload '%ld'\n",plen);
        free(keydesc);
        return(-1);
    }

    _kafs_dbg("plen=%zu tklen=%lu rk=%zu\n",
           plen, creds->ticket.length, sizeof(*payload));

    /* use version 1 of the key data interface */
    payload->kver           = 1;
    payload->security_index = 2;
    payload->ticket_length  = creds->ticket.length;
    payload->expiry         = creds->times.endtime;
    payload->kvno           = RXKAD_TKT_TYPE_KERBEROS_V5;

    ret = _kafs_derive_des_key(creds->session.keytype,
                         creds->session.keyvalue.data,
                         creds->session.keyvalue.length,
                         payload->session_key);
    if( ret == -1 ) {
        _kafs_dbg("_kafs_derive_des_key failed\n");
        free(keydesc);
        free(payload);
        return(-1);
    }

    memcpy(payload->ticket, creds->ticket.data, creds->ticket.length);

    key_serial_t kt;
    kt = add_key(_KAFS_KEY_SPEC_RXRPC_TYPE, keydesc, payload, plen, KEY_SPEC_SESSION_KEYRING);
    if( kt < 0 ){
        _kafs_dbg_errno("unable to add rxrpc key\n");
    }

    free(keydesc);
    free(payload);

    if( kt == - 1 ) return(-1);
    return(0);
}

/* ============================================================================= */

int _kafs_invalidate_key(key_serial_t parent,key_serial_t key, char *desc, int desc_len, void *data)
{
    if( desc == NULL ){
        _kafs_dbg("key with no desription (%d)\n",key);
        return(0);
    }
    if(strstr(desc,_KAFS_KEY_SPEC_RXRPC_TYPE) == desc ){
        _kafs_dbg("invalidating key '%s' in the session keyring\n",desc);
        long ret = keyctl_invalidate(key);
        if( ret == -1 ){
            _kafs_dbg_errno("unable to invalidate key '%s' in the session keyring\n",desc);
        }
    } else {
        _kafs_dbg("incorrect type for the key '%s'\n",desc);
    }

    return(0);
}

/* ============================================================================= */

int _kafs_list_key(key_serial_t parent,key_serial_t key, char *desc, int desc_len, void *data)
{
    int ret;
    int nkey = 0;
    if( desc == NULL ){
        _kafs_dbg("key with no desription (%d)\n",key);
        return(nkey);
    }
    if(strstr(desc,_KAFS_KEY_SPEC_RXRPC_TYPE) != desc ){
        _kafs_dbg("incorrect type for the key '%s'\n",desc);
        return(nkey);
    }

    char*   keystr;

    ret = asprintf(&keystr, "%08x", key);
    if( ret == -1 ) {
        errno = ENOMEM;
        _kafs_dbg_errno("unable to create keystr for key '%d'\n",key);
        return(nkey);
    }

    FILE* p_fk = fopen(_KAFS_PROC_KEYS,"r");
    if( p_fk ){
        char buf[PATH_MAX];
        char tmp[PATH_MAX];
        char name[PATH_MAX];
        char exp[PATH_MAX];

        while( fgets(buf,sizeof(buf),p_fk) != NULL ){
            if( strstr(buf,keystr) == buf ){
                /* THIS IS HORRIBLE :-( but it should be safe as all buffers are of the same size
                   and buf is \0 terminated */
                sscanf(buf,"%s %s %s %s %s %s %s %s %s",tmp,tmp,tmp,exp,tmp,tmp,tmp,tmp,name);
                printf("%-30s %6s\n",name,exp);
                nkey++;
            }
        }
        fclose(p_fk);
    }

    free(keystr);

    return(nkey);
}

/* ============================================================================= */
