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

#define _GNU_SOURCE
#include <stdio.h>
#include <krb5.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/limits.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <kafs-user.h>
#include <kafs_locl.h>

/* ============================================================================= */

int k_hasafs(void)
{
    _kafs_dbg("-> k_hasafs\n");

    FILE* p_f = fopen(_PATH_KAFS_MOD,"r");
    if( p_f ){
        /* only presence of the file is determined, not its contents */
        fclose(p_f);
        _kafs_dbg("kAFS is present\n");
        return(1);
    }
    _kafs_dbg("kAFS is NOT present\n");
    return(0);
}

/* ============================================================================= */

int k_setpag(void)
{
    _kafs_dbg("-> k_setpag\n");

    char buf[PATH_MAX];
    snprintf(buf,PATH_MAX,_KAFS_LOCAL_SES_NAME);

    /* create new local session keyring */
    key_serial_t kt = keyctl_join_session_keyring(buf);
    if( kt == -1 ) {
        _kafs_dbg_errno("unable to join session keyring '%s'\n",buf);
        return(-1);
    }

    /* link user keyring into the session */
    long err = keyctl_link(KEY_SPEC_USER_KEYRING,kt);
    if( err == -1 ){
        _kafs_dbg_errno("unable to link user keyring to the session keyring: %d\n",kt);
        return(-1);
    }
    return(0);
}

/* ============================================================================= */

int k_setpag_shared(void)
{
    _kafs_dbg("-> k_setpag_shared\n");
    char buf[PATH_MAX];

    snprintf(buf,PATH_MAX,_KAFS_SHARED_SES_NAME);

    /* join or create global user session keyring */
    key_serial_t kt = keyctl_join_session_keyring(buf);
    if( kt == -1 ) {
        _kafs_dbg_errno("unable to join the session keyring: '%s'\n",buf);
        return(-1);
    }

    /* set permission so we can join the keyring later - ignore error */
    long err = keyctl_setperm(kt, KEY_POS_ALL | KEY_USR_ALL);
    if( err == -1 ){
        _kafs_dbg_errno("unable to set permision for the session keyring: %d\n",kt);
    }

    /* link user keyring into the session */
    err = keyctl_link(KEY_SPEC_USER_KEYRING,kt);
    if( err == -1 ){
        _kafs_dbg_errno("unable to link user keyring to the session keyring: %d\n",kt);
        return(-1);
    }

    return(0);
}

/* ============================================================================= */

int k_haspag(void)
{
    _kafs_dbg("-> k_haspag\n");

    char* desc;
    int ret = 0;

    if( keyctl_describe_alloc(KEY_SPEC_SESSION_KEYRING,&desc) == -1 ){
        return(ret); /* no session keyring */
    }
    if( strstr(desc,_KAFS_LOCAL_SES_NAME) ){
        ret = 1;
    }
    if( strstr(desc,_KAFS_SHARED_SES_NAME) ){
        ret = 2;
    }
    free(desc);

    return(ret);
}

/* ============================================================================= */

int k_unlog(void)
{
    _kafs_dbg("-> k_unlog\n");
    recursive_session_key_scan(_kafs_invalidate_key,NULL);
    return(0);
}

/* ============================================================================= */

int k_unlog_cell(char* cell)
{
    _kafs_dbg("-> k_unlog_cell\n");

    if( cell == NULL ){
        errno = EINVAL;
        return(-1);
    }

    char*   keydesc;
    long    ret;

    ret = asprintf(&keydesc, "afs@%s", cell);
    if( ret == -1 ) {
        errno = ENOMEM;
        _kafs_dbg_errno("unable to create key description for cell '%s'\n",cell);
        return(-1);
    }

    /* try to find the token */
    key_serial_t kt = keyctl_search(KEY_SPEC_SESSION_KEYRING,_KAFS_KEY_SPEC_RXRPC_TYPE,keydesc, 0);
    if( kt == -1 ) {
        _kafs_dbg_errno("'%s' key not found in the session keyring\n",keydesc);
        free(keydesc);
        return(-1);
    }

    ret = keyctl_invalidate(kt);
    if( ret == -1 ){
        _kafs_dbg_errno("unable to invalidate key '%s' (%d) in the session keyring\n",keydesc,kt);
    }

    free(keydesc);
    return(ret);
}

/* ============================================================================= */

int k_list_tokens(void)
{
    _kafs_dbg("-> k_list_tokens\n");

    printf("# Token                        Expire\n");
    printf("# ---------------------------- ------\n");

    int ntk = recursive_session_key_scan(_kafs_list_key,NULL);
    return(ntk);
}

/* ============================================================================= */

void kafs_set_verbose(int level)
{
    _kafs_debug = level;
}

/* ============================================================================= */

void kafs_print_version(char* progname)
{
    if( progname ) {
        printf("kAFS-user - %s (1.0.x)\n",progname);
    } else {
        printf("kAFS-user (1.0.x)\n");
    }
    printf("(c) 2021 Petr Kulhanek\n");
    printf("This work is derived from:\n");
    printf("  Heimdal: Copyright 1995-2014 Kungliga Tekniska Högskolan\n");
    printf("  kafs-client:  Copyright (C) 2017 Red Hat, Inc. All Rights Reserved.\n");
    printf("                Written by David Howells (dhowells@redhat.com)\n");
}

/* ============================================================================= */

char* kafs_get_this_cell(void)
{
    _kafs_dbg("-> kafs_get_this_cell\n");

    FILE* p_f = fopen(_PATH_KAFS_USER_THISCELL, "r");
    if( p_f == NULL ){
        _kafs_dbg_errno("unable to open file '%s'\n",_PATH_KAFS_USER_THISCELL);
        return(NULL);
    }

    char  _kafs_buff[NAME_MAX];
    if( fgets(_kafs_buff,sizeof(_kafs_buff),p_f) == NULL ){
        _kafs_dbg("unable to read line from '%s'\n",_PATH_KAFS_USER_THISCELL);
        fclose(p_f);
        return(NULL);
    }

    /* remove trailing \n */
    char* pos = strchr(_kafs_buff, '\n');
    if( pos != NULL ) *pos = '\0';

    char* p_cell = strdup(_kafs_buff);
    if( p_cell == NULL ){
        _kafs_dbg("unable to allocate '%s'\n",_kafs_buff);
    }

    fclose(p_f);
    return(p_cell);
}

/* ============================================================================= */

char** kafs_get_these_cells(void)
{
    _kafs_dbg("-> kafs_get_these_cells\n");

    char* _kafs_these_cells[_KAFS_MAX_LIST];
    char  _kafs_buff[NAME_MAX];

    /* https://docs.openafs.org/Reference/5/ThisCell.html */

    const char* fns[] = {
                _PATH_KAFS_USER_THESECELLS,
                _PATH_KAFS_USER_THISCELL,
                NULL };
    const char** fn = fns;

    int num_of_cells = 0;

    while( *fn != NULL ){
        FILE* p_f = fopen(*fn, "r");
        if( p_f == NULL ){
            _kafs_dbg_errno("unable to open file '%s'\n",*fn);
            fn++;
            /* this error is ignored */
            continue;
        }

        while( fgets(_kafs_buff,sizeof(_kafs_buff),p_f) != NULL ){
            /* remove trailing \n */
            char* pos = strchr(_kafs_buff, '\n');
            if( pos != NULL ) *pos = '\0';

            /* is it already present? */
            int i;
            for(i=0; i < num_of_cells; i++ ){
                if( strcmp(_kafs_these_cells[i],_kafs_buff) == 0 ) break;
            }
            if( i < num_of_cells ) {
                _kafs_dbg(" duplicate: '%s'\n",_kafs_buff);
                continue;
            }

            /* insert */
            _kafs_these_cells[num_of_cells] = strdup(_kafs_buff);
            if( _kafs_these_cells[num_of_cells] == NULL ) {
                _kafs_dbg(" out-of-memory: '%s'\n",_kafs_buff);
                for(int i=0; i < num_of_cells; i++) free(_kafs_these_cells[i]);
                errno = ENOMEM;
                return(NULL);
            }
            num_of_cells++;
            _kafs_dbg(" added: '%s'\n",_kafs_buff);
        }
        fclose(p_f);
        fn++;
    }

    /* generate NULL terminated list of strings */

    char** p_list = calloc(num_of_cells+1,sizeof(char*));
    if( p_list == NULL ){
        for(int i=0; i < num_of_cells; i++) free(_kafs_these_cells[i]);
        _kafs_dbg(" out-of-memory: the main list size '%d'\n",num_of_cells+1);
        errno = ENOMEM;
        return(NULL);
    }
    for(int i=0; i < num_of_cells; i++) p_list[i] = _kafs_these_cells[i];
    p_list[num_of_cells] = NULL;

    return(p_list);
}

/* ============================================================================= */

void kafs_free_these_cells(char** cells)
{
    _kafs_dbg("-> kafs_free_these_cells\n");

    if( cells == NULL ) return;

    char** p_ic    = cells;
    while( *p_ic != NULL ){
        free(*p_ic);
        p_ic++;
    }

    free(cells);
}

/* ============================================================================= */

char** kafs_get_vls(char* cell)
{
    _kafs_dbg("-> kafs_get_vls\n");

    if( cell == NULL ){
        errno = EINVAL;
        return(NULL);
    }

    FILE* p_afsdb = fopen(_PATH_KAFS_USER_CELLSERVDB,"r");
    if( p_afsdb == NULL ){
        _kafs_dbg_errno("unable to open CELLSRVDB file '%s'\n",_PATH_KAFS_USER_CELLSERVDB);
        return(NULL);
    }

    char*   celldesc;
    int     ret;

    ret = asprintf(&celldesc, ">%s ", cell);
    if( ret == -1 ) {
        fclose(p_afsdb);
        _kafs_dbg("unable to create description for cell '%s'\n",cell);
        errno = ENOMEM;
        return(NULL);
    }

    char* _kafs_vls[_KAFS_MAX_LIST];
    char  _kafs_buff[NAME_MAX];

    int num_of_vls = 0;

    /* https://docs.openafs.org/Reference/5/CellServDB.html */

    while( fgets(_kafs_buff,sizeof(_kafs_buff),p_afsdb) != NULL ){
        if( strstr(_kafs_buff,celldesc) == _kafs_buff ){
            /* cell found - read VLS */
            while( fgets(_kafs_buff,sizeof(_kafs_buff),p_afsdb) != NULL ){
                /* FIXME - currently ignore IP in [], which is optional */
                if( isdigit(_kafs_buff[0]) == 0 ) break;

                char  _kafs_ip[NAME_MAX];
                sscanf(_kafs_buff,"%s",_kafs_ip);
                _kafs_vls[num_of_vls] = strdup(_kafs_ip);
                if( _kafs_vls[num_of_vls] == NULL ) {
                    _kafs_dbg(" out-of-memory: '%s'\n",_kafs_buff);
                    for(int i=0; i < num_of_vls; i++) free(_kafs_vls[i]);
                    errno = ENOMEM;
                    return(NULL);
                    }
                num_of_vls++;
                _kafs_dbg(" added: '%s'\n",_kafs_ip);
            }
            break;
        }
    }
    fclose(p_afsdb);

    /* generate NULL terminated list of strings */

    char** p_list = calloc(num_of_vls+1,sizeof(char*));
    if( p_list == NULL ){
        for(int i=0; i < num_of_vls; i++) free(_kafs_vls[i]);
        _kafs_dbg(" out-of-memory: the main list size '%d'\n",num_of_vls+1);
        errno = ENOMEM;
        return(NULL);
    }
    for(int i=0; i < num_of_vls; i++) p_list[i] = _kafs_vls[i];
    p_list[num_of_vls] = NULL;

    return(p_list);
}

/* ============================================================================= */

void kafs_free_vls(char** vls)
{
    _kafs_dbg("-> kafs_free_vls\n");

    if( vls == NULL ) return;

    char** p_ic    = vls;
    while( *p_ic != NULL ){
        free(*p_ic);
        p_ic++;
    }

    free(vls);
}

/* ============================================================================= */

krb5_error_code krb5_afslog(krb5_context context,
                 krb5_ccache id,
                 const char* cell,
                 const char* realm)
{
    _kafs_dbg("-> krb5_afslog\n");

    krb5_error_code err = -1;

    if( (cell != NULL) && (realm != NULL) ){
        _kafs_dbg("using _kafs_set_afs_token_2 (cell: %s, realm: %s)\n",cell,realm);
        return(_kafs_set_afs_token_2(context,id,cell,realm));
    }
    if( (cell != NULL) && (realm == NULL) ){
        _kafs_dbg("using _kafs_set_afs_token_1 (cell: %s)\n",cell);
        return(_kafs_set_afs_token_1(context,id,cell));
    }

    /* for all cells in TheseCells and ThisCell */
    char** p_cells = kafs_get_these_cells();
    if( p_cells == NULL ){
        _kafs_dbg("no cells in TheseCells and ThisCell\n");
        return(-1);
    }

    char** p_ic    = p_cells;
    while( *p_ic != NULL ){
        _kafs_dbg("using _kafs_set_afs_token_1 (cell: %s)\n",*p_ic);
        err = _kafs_set_afs_token_1(context,id,*p_ic);
        if( err != 0 ) break;
        p_ic++;
    }
    kafs_free_these_cells(p_cells);

    return(err);
}

/* ============================================================================= */
