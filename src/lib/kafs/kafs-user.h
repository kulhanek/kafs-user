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

#ifndef __KAFS_H
#define __KAFS_H

/* ============================================================================= */

/* is kAFS loaded?
 * return values:
 *  0 - not present
 *  1 - present
*/
int k_hasafs(void);

/* do we have PAG?
 * return values:
 *  0 NO
 *  1 local PAG
 *  2 shared PAG
*/
int k_haspag(void);

/* set new anonymous PAG
 * return values:
 *  0 OK
 * -1 error with details in errno
*/
int k_setpag(void);

/* set or join shared PAG
 * return values:
 *  0 OK
 * -1 error with details in errno
*/
int k_setpag_shared(void);

/* destroy all AFS tokens
 * return values:
 *  0 OK
 * -1 error with details in errno
*/
int k_unlog(void);

/* destroy AFS token for given cell
 * return values:
 *  0 OK
 * -1 error with details in errno
*/
int k_unlog_cell(char* cell);

/* list tokens
 * return values:
 *  the number of AFS tokens
*/
int k_list_tokens(void);

/* ============================================================================= */

/* print version */
void kafs_print_version(char* progname);

/* set verbose handler */
void kafs_set_verbose(int level);

/* ============================================================================= */

/* return these cells as NULL terminated list of strings */
char** kafs_get_these_cells(void);

/* free these cells returned by kafs_get_these_cells */
void kafs_free_these_cells(char** cells);

/* return name of root cell, the name must be freed by free() */
char* kafs_get_this_cell(void);

/* ============================================================================= */

/* return volume location servers for given cell as NULL terminated list of strings */
char** kafs_get_vls(char* cell);

/* free volume location servers returned by kafs_get_vls */
void kafs_free_vls(char** vls);

/* ============================================================================= */

/* create AFS token
 * cell == NULL -> all cells in TheseCells and ThisCell are used, realm is ignored
 * cell != NULL, realm == NULL, REALM is determined from krb5.conf
 * note: context and id must be initialized prior calling this function
 * return values:
 *    0 - OK
 *   -1 - error with details in errno
 *   >0 - krb5 error
 */
krb5_error_code krb5_afslog(krb5_context context,
                 krb5_ccache id,
                 const char* cell,
                 krb5_const_realm realm);

/* ============================================================================= */

#define _KAFS_PROC_CELLS            "/proc/fs/afs/cells"
#define _KAFS_PROC_ROOT_CELL        "/proc/fs/afs/rootcell"

#define _KAFS_LOCAL_SES_NAME        "_ses.locpag"
#define _KAFS_SHARED_SES_NAME       "_ses.shrpag"
#define _PATH_KAFS_MOD              "/sys/module/kafs/initstate"

#define _KAFS_MAX_LIST              1024
#define _KAFS_KEY_SPEC_RXRPC_TYPE   "rxrpc"
#define _KAFS_PROC_KEYS             "/proc/keys"

#define _PATH_KAFS_USER_ETC  		"/etc/kafs-user/"
#define _PATH_KAFS_USER_THISCELL	_PATH_KAFS_USER_ETC "ThisCell"
#define _PATH_KAFS_USER_THESECELLS	_PATH_KAFS_USER_ETC "TheseCells"
#define _PATH_KAFS_USER_CELLSERVDB 	_PATH_KAFS_USER_ETC "CellServDB"

#define _KAFS_DEBUG_FILE            "/tmp/kafs"

/* ============================================================================= */

#endif /* __KAFS_H */
