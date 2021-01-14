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
#include <getopt.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================== */

void print_usage(void)
{
    printf("\n");
    printf("Print available AFS tokens.\n");
    printf("\n");
    printf("Usage: tokens [-vdh]\n");
    printf("\n");
    printf("Options:\n");
    printf("   -h   Print this help.\n");
    printf("   -v   Print kAFS-user version.\n");
    printf("   -d   Be more verbose.\n");
    printf("\n");
}

/* ========================================================================== */

int main(int argc, char **argv)
{
    int             c;

    while ((c = getopt(argc, argv, "hvd")) != -1) {
        switch (c) {
            case 'h':
                print_usage();
                return(0);
            case '?':
            default:
                print_usage();
                return(1);
            case 'v':
                kafs_print_version(NULL);
                return(0);
            case 'd':
                kafs_set_verbose(1);
                break;
        }
    }

    if( ! k_hasafs() ) errx(1, "AFS does not seem to be present on this machine");

    /* list tokens */

    int nkt = k_list_tokens();
    if( nkt == 0 ){
        printf(">> NO AFS TOKENS\n");
    }

    return 0;
}
