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
int              verbose;

struct getargs args[] = {
    { "verbose",'v', arg_flag, &verbose, NULL, NULL },
    { "version", 0,  arg_flag, &version_flag, NULL, NULL },
    { "help",	'h', arg_flag, &help_flag, NULL, NULL },
};

static int num_args = sizeof(args) / sizeof(args[0]);

/* ========================================================================== */

void usage(int ecode)
{
    arg_printusage(args, num_args, NULL, NULL);
    exit(ecode);
}

/* ========================================================================== */

int main(int argc, char **argv)
{
    int optidx = 0;

    if( getarg(args, num_args, argc, argv, &optidx) ) usage(1);

    if( help_flag ) usage(0);

    if( version_flag ) {
        kafs_print_version(NULL);
        exit(0);
    }

    if( verbose ) kafs_set_verbose(1);

    if( ! k_hasafs() ) errx(1, "AFS does not seem to be present on this machine");

    /* list tokens */

    int nkt = k_list_tokens();
    if( nkt == 0 ){
        printf(">> NO AFS TOKENS\n");
    }

    return 0;
}
