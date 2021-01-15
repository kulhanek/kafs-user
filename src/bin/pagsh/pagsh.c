/* Copyright (c) 2021 Petr Kulhanek (kulhanek@chemi.muni.cz)
 * Support for kAFS (kernel AFS) adapted from Heimdal libkafs,
 * kafs-client and pam-afs-session.
 */
/*
 * Copyright (c) 1995 - 2005 Kungliga Tekniska Högskolan
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <pwd.h>

#include <krb5.h>
#include <kafs-user.h>

#include <err.h>
#include <errno.h>
#include <getopt.h>

/* ========================================================================== */

int c_flag          = 0;
int c_shared_pag    = 0;
int verbose         = 0;

/* ========================================================================== */

void print_usage(void)
{
    printf("\n");
    printf("Start new shell or command in a new PAG (process authentication group).\n");
    printf("\n");
    printf("Usage: newpag [-vdhcs]\n");
    printf("\n");
    printf("Options:\n");
    printf("   -h   Print this help.\n");
    printf("   -v   Print kAFS-user version.\n");
    printf("   -d   Be more verbose.\n");
    printf("   -c   Run command.\n");
    printf("   -s   Create shared PAG.\n");
    printf("\n");
}
/* ========================================================================== */

int main(int argc, char **argv)
{
    int             c;

    while ((c = getopt(argc, argv, "hvdcs")) != -1) {
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
                verbose = 1;
                break;
            case 's':
                c_shared_pag = 1;
                break;
            case 'c':
                c_flag = 1;
                break;
        }
    }

    printf("Current: %d\n",k_haspag());

    argc -= optind;
    argv += optind;

    int i = 0;

    /* FIXME +10 - why? */
    char** args = (char **) malloc((argc + 10)*sizeof(char *));
    if (args == NULL)
	errx (1, "Out of memory allocating %lu bytes",
	      (unsigned long)((argc + 10)*sizeof(char *)));

    char* path;
    char* p;
    if( *argv == NULL ) {
        path = getenv("SHELL");
        if( path == NULL ) path = strdup("/bin/sh");
    } else {
        path = strdup(*argv++);
    }
    if (path == NULL) errx (1, "Out of memory copying path");

    p=strrchr(path, '/');
    if(p){
        args[i] = strdup(p+1);
    } else {
        args[i] = strdup(path);
    }

    if( args[i++] == NULL ) errx (1, "Out of memory copying arguments");

    while(*argv) args[i++] = *argv++;
    args[i++] = NULL;

    /* create PAG */

    if( k_hasafs() ) {
        if( c_shared_pag ) {
            k_setpag_shared();
        } else {
            k_setpag();
        }
    }

    /* execute shell or command */

    execvp(path, args);
    if (errno == ENOENT || c_flag) {
        /* FIXME +2 - why? */
        char **sh_args = malloc ((i + 2) * sizeof(char *));

        if (sh_args == NULL) errx (1, "Out of memory copying sh arguments");

        sh_args[0] = "sh";
        sh_args[1] = "-c";
        sh_args[2] = path;
        for(int j = 1; j < i; ++j) sh_args[j + 2] = args[j];

        execv ("/bin/sh", sh_args);
    }
    err (1, "execvp");
}
