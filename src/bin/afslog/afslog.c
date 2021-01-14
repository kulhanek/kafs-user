/* Copyright (c) 2021 Petr Kulhanek (kulhanek@chemi.muni.cz)
 * Support for kAFS (kernel AFS) adapted from Heimdal libkafs,
 * kafs-client and pam-afs-session.
 */
/*
 * Copyright (c) 1997-2003 Kungliga Tekniska Högskolan
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

#include <ctype.h>
#include <krb5.h>
#include <kafs-user.h>
#include <getarg.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================== */
int              help_flag;
int              version_flag;
getarg_strings   cells;
char*            client_string;
char*            cache_string;
char*            realm;
int              unlog_flag;
int              verbose;

struct getargs args[] = {
    { "cell",	'c', arg_strings, &cells, "cell to log into", "name" },
    { "realm",	'k', arg_string, &realm, "realm for afs cell", "name" },
    { "unlog",	'u', arg_flag, &unlog_flag, "remove all tokens", NULL },
    { "principal",'P',arg_string,&client_string,"principal to use","name"},
    { "cache",   0,  arg_string, &cache_string, "ccache to use", "name"},
    { "verbose",'v', arg_flag, &verbose, NULL, NULL },
    { "version", 0,  arg_flag, &version_flag, NULL, NULL },
    { "help",	'h', arg_flag, &help_flag, NULL, NULL },
};

static int num_args = sizeof(args) / sizeof(args[0]);

/* ========================================================================== */

void usage(int ecode)
{
    arg_printusage(args, num_args, NULL, "[cell1 [cell2] ...]");
    exit(ecode);
}

/* ========================================================================== */

int main(int argc, char **argv)
{
    krb5_error_code ret = 0;
    krb5_context    context;
    krb5_ccache     id     = NULL;
    int             optidx = 0;
    int i;
    int num;

    int             failed = 0;

    if( getarg(args, num_args, argc, argv, &optidx) ) usage(1);

    if( help_flag ) usage(0);

    if( version_flag ) {
        kafs_print_version(NULL);
        exit(0);
    }

    if( verbose ) kafs_set_verbose(1);

    if( ! k_hasafs() ) errx(1, "AFS does not seem to be present on this machine");

    if( unlog_flag ){
        k_unlog();
        exit(0);
    }

    ret = krb5_init_context(&context);
    if( ret ) errx(1, "Unable to get Krb5 context");

    if( client_string ) {
        krb5_principal client;
        ret = krb5_parse_name(context, client_string, &client);
        if( ret == 0 ) ret = krb5_cc_cache_match(context, client, &id);
        if( ret ) errx(1, "Unable get ccache from specified principal");
        krb5_free_principal(context, client);
    }

    if( id == NULL && cache_string ) {
        ret = krb5_cc_resolve(context, cache_string, &id);
        if( ret ) errx(1, "Unable to open specified ccache");
    }

    if( id == NULL ){
        ret = krb5_cc_default(context, &id);
        if( ret ) errx(1, "Unable to get default ccache");
    }

    /* afslog */

    num = 0;
    for(i = 0; i < cells.num_strings; i++){
        if( verbose ) warnx("Getting tokens for cell \"%s\"", cells.strings[i]);
        ret = krb5_afslog(context, id, cells.strings[i], realm);
        if( ret ) failed++;
        num++;
    }
    free_getarg_strings(&cells);

    for(i = optidx; i < argc; i++){
        if( verbose ) warnx("Getting tokens for cell \"%s\"", argv[i]);
        ret = krb5_afslog(context, id, argv[i], realm);
        if( ret ) failed++;
        num++;
    }
    if( num == 0 ) {
        if( verbose ) warnx("Getting tokens for default cells");
        ret = krb5_afslog(context, id, argv[i], realm);
        if( ret ) failed++;
    }

    /* clean-up */
    krb5_cc_close(context,id);
    krb5_free_context(context);

    return failed;
}
