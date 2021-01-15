# kAFS-user #
This package provides user space commands to setup and use kAFS (kernel AFS) designed and tested for Ubuntu.

At our site, we operate computers, which require support for both Kerberos and AFS. Kerberos is used to mount NFS data storages with job data using the sec=krb5* security flavour, for obtaining tokens for AFS, which stores software modules (possibly restricted to some users), and for job submissions employing PBSPro batch system. PBSPro contains official support for Kerberos ticket and AFS tokens renewals. However, this support is available only for OpenAFS implementation (for example, using libkafs from Heimdal).

For Krb5+OpenAFS, the typical setup is:
* openssh with UsePAM and GSSAPIAuthentication to create Krb5 ccache for GSSAPI with delegations
* pam_krb5 PAM module to create Krb5 ccache from password athentication
* pam_afs_session PAM module to create PAG and AFS tokens
* PBSPro compiled with Kerberos and AFS setup

This setup has some limitations. Typically, it is very hard to perform synchronized renewal (manual) of Kerberos tickets and AFS tokes inside various sessions (login sessions (konsole terminals), remote sessions, user@*.service sessions (gnome terminals), etc.) Moreover, this setup lacks support of kernel AFS or the support is very limited.

Solutions employing KEYRING or KCM (heimdal-kcm or sssd) types of Kerberos credential cache (ccache) partially solves the problem with Kerberos ccache sharing but it still lacks support for renewal of AFS tokes because the tokens are  stored into independent storages (PAGs).

kAFS-user package aims to provide solution for Kerberos and kernel AFS, which overcomes aforementioned limitations.


## AFS Token Manipulation ##
The package provides commands for manipulation with AFS tokens:
* afslog.kafs - create AFS tokens if valid TGT ticket is available
* tokens.kafs - list AFS tokens and their expiration times
* unlog.kafs - destroy AFS tokens
* pagsh.kafs - create local or shared PAG and run a command or shell within it


## PAG ##
The PAG (Process Authentication Goup) in the kAFS-user implementation is nothing else than a session keyring. Two types of PAGs are supported:
* local PAG
* shared PAG

The local PAG is a session keyring unique for each login session. On contrary, the shared PAG
is represented by one named session keyring unique for a user, which is then shared among multiple login sessions.

# Installation and Setup of kAFS-user #

## Installation ##
1) Install necessary dependencies:
```bash
MIT Krb5:
$ sudo apt-get install krb5-multidev libpam0g-dev libkeyutils-dev

Heimdal Krb5:
$ sudo apt-get install heimdal-multidev libpam0g-dev libkeyutils-dev
```

2) Download the source code. Update CMakeList.txt if necessary, then compile and install the code.
```bash
$ git clone https://github.com/kulhanek/kafs-user.git
$ cd kafs-user
$ cmake .
$ make
$ sudo make install
```

## Setup kAFS ##
1) Configure CellServDB, TheseCells, and ThisCell files in the /etc/kafs-user/ directory. Their meaning and syntax
is the same as for OpenAFS. Configuration using AFSDB DNS is not supported.

2) Enable the afs.mount unit for its automatic start at boot.
```bash
$ sudo systemctl enable afs.mount
```

3) Either reboot or mount it manually.
```bash
$ sudo systemctl start afs.mount
```

## pam-kafs-session ##
This is a PAM module, which creates AFS tokens when logged to a system for users with valid TGT ticket
(possibly comming from pam_krb5, or ssh with GSSAPIDelegateCredentials yes).
Default AFS cells are taken from TheseCells and ThisCell files.

The configuration options are as follows:
* verbosity - verbosity level, 0 - only errors, 1 - notifications, 2 - debugging information (default: 0)
* minimum_uid - minimum uid for which PAG and AFS tokens should be created (default: 1000)
* create_pag - create local/shared PAGs (yes) or keep default session keyring possibly created by pam_keyinit (no) (default: yes)
* shared_pag - create shared PAG (default: no)
* locpag_for_pam - use local PAG for given PAM service module (default: NULL)
* locpag_for_user - use local PAG for given target user name (default: NULL)
* locpag_for_principal  - use local PAG for ccache default principal (default: NULL)
* create_tokens - create AFS tokens (default: yes)
* convert_cc_to - convert CCACHE to given type if it is different (default: NULL), supported types are KCM and KEYRING

locpag_for_pam, locpag_for_user, locpag_for_principal are specified as fnmatch() extended pattern. The configuration can be changed using /etc/krb5.conf in [appdefaults]/pam-kafs-session.

## Tested configurations ##
```bash
[libdefaults]
    default_ccache_name = KEYRING:persistent

[appdefaults]
    pam = {
        ccache = FILE:/tmp/krb5cc_%u_XXXXXX
    }
    pam-kafs-session = {
        shared_pag  = true
        convert_cc_to = KEYRING
        locpag_for_user = +(admin|manager)
    }
```

# Detailed Analysis #

## Ubuntu 18.04 LTS ##

* sshd
  * all sshd processes run within the same session keyring under root
  * GSSAPIAuthentication
    * if succesfull and GSSAPIDelegateCredentials, the Kerberos ticket is stored into ccache
    * KRB5CCNAME is set to FILE:/tmp/krb5cc_[uid]_[random]
    * the ccache name cannot be change as it is hardcoded, see [report](https://bugs.launchpad.net/ubuntu/+source/openssh/+bug/1889548)
    * anyway, it would be BAD idea to use KEYRING or KCM at this stage without proper handling by OpenSSH
      * KEYRING would be stored into the shared session keyring owned by root
      * KCM will create ccache under root, which makes it inaccessible to given user later
  * PAM stack
    * PAM auth
      * pam_krb5
        * if correct password is provided, the module creates temporary Krb5 ccache of FILE type (under root)
    * PAM account
      * pam_krb5  - check .k5login?
    * PAM setcred (PAM_ESTABLISH_CRED)
      * [pam_keyinit - while this is implemented in PAM module, it is not called (luckily) under Ubuntu]
      * pam_krb5
        * move the temporary ccache to target destination, this is done under root
        * KRB5CCNAME is set to FILE:/tmp/krb5cc_UID_RANDOM. The name can be configured by ccache and ccache_dir options.
        * for FILE type, the proper file permissions for the target user are set
        * it is BAD idea to use KEYRING or KCM ccache types
          * KEYRING would be stored into common session keyring owned by root
          * KCM would store ccache for root and not for given user
      * pam_kafs_session - implemented, but it does nothing
    * PAM session - open
      * pam_keyinit - it initializes a new anonymous session keyring (_ses), it saves its ID
        * at this point, KEYRING ccache and other keys in the session keyring, if previously created by pam_krb5 or others, will disappear
      * pam_krb5 - it does nothing?
      * pam_kafs_session (run under the target user)
        * it creates PAG (optional)
        * it converts Krb5 ccache to requested type (optional)
        * it creates AFS tokens (optional)
    * sshd forking, the process is reowned to the user at some point
        * PAM setcred (PAM_ESTABLISH_CRED)
          * pam_keyinit - it is not called under Ubuntu
          * pam_krb5 - does nothing
          * pam_kafs_session - implemented, but it does nothing
        * USER SESSION
        * process termination
    * PAM session - close
      * pam_keyinit - it revokes the session keyring using saved ID
      * pam_krb5  - it does nothing?
      * pam_kafs_session - implemented, but it does nothing
    * PAM setcred (PAM_DELETE_CRED)
      * pam_keyinit - it is not called
      * pam_krb5  - probably destroy ccache?
      * pam_kafs_session - destroy AFS tokens if not shared PAG, revoke local PAG
    * process termination


* gdm-password (login), PAM stack
  * PAM auth
    * pam_krb5
      * if correct password is provided, the module creates temporary Krb5 ccache of FILE type (under root)
  * PAM account
    * pam_krb5  - check .k5login?
  * PAM setcred (PAM_ESTABLISH_CRED)
    * [pam_keyinit - while this is implemented in PAM module, it is not called (luckily) under Ubuntu]
    * pam_krb5
      * move the temporary ccache to target destination, this is done under root
      * KRB5CCNAME is set to FILE:/tmp/krb5cc_UID_RANDOM. The name can be configured by ccache and ccache_dir options.
      * for FILE type, the proper file permissions for the target user are set
      * it is BAD idea to use KEYRING or KCM ccache types
        * KEYRING would be stored into common session keyring owned by root
        * KCM would store ccache for root and not for given user
    * pam_kafs_session - implemented, but it does nothing
  * PAM session - open
    * pam_keyinit - it initializes a new anonymous session keyring (_ses), it saves its ID
      * at this point, KEYRING ccache and other keys in the session keyring, if previously created by pam_krb5 or others, will disappear
    * pam_krb5 - it does nothing?
    * pam_kafs_session (run under the target user)
      * it creates PAG (optional)
      * it converts Krb5 ccache to requested type (optional)
      * it creates AFS tokens (optional)
  * USER SESSION
  * the rest is simmilar to sshd


* gdm-password (unlock)
  * PAM auth
    * pam_krb5
      * if correct password is provided, the module creates temporary Krb5 ccache of FILE type (under root)
  * PAM account
    * pam_krb5  - check .k5login?
  * PAM setcred (PAM_REINITIALIZE_CRED)
    * [pam_keyinit - it is not called]
    * pam_krb5 - move the temporary ccache to target destination determined by KRB5CCNAME
      * the transfer is done under root, problematic for KCM ccache
    * pam_kafs_session
      * it renews AFS tokens (optional)


* systemd-user, PAM stack
  * PAM account
    * pam_krb5  - check .k5login?
  * PAM setcred (PAM_ESTABLISH_CRED)
    * [pam_keyinit - it is not called], but the session keyring is probably created in advance by systemd-user
    * pam_krb5
      * no PAM_KRB5CCNAME, assuming non-Kerberos login
    * pam_kafs_session  - implemented, but it does nothing
  * PAM session - open
    * [pam_keyinit - it is not called]
    * pam_krb5 - it does nothing?
    * pam_kafs_session (run under the target user)
      * it creates PAG (optional)
      * it converts Krb5 ccache to requested type (optional)
      * it creates AFS tokens (optional)
      * BUT two last points due to missing KRB5CCNAME will silently fail


## Final design of pam_kafs_session ##
* PAM setcred
  * PAM_ESTABLISH_CRED - implemented, but it does nothing
  * PAM_REINITIALIZE_CRED - renew AFS tokes if ccache is available, but do not alter PAG
  * PAM_REFRESH_CRED - renew AFS tokes if ccache is available, but do not alter PAG
  * PAM_DELETE_CRED - destroy AFS tokens if not shared PAG, revoke local PAG
* PAM session - open (all operations are performed under the target user)
  * it creates PAG (optional)
  * it converts Krb5 ccache to requested type (optional)
  * it creates AFS tokens (optional)
* PAM session - close - implemented, but it does nothing
* security:
  * the module does nothing in setuid environment (su, sudo, etc.)
  * TODO: check safety in multi-threaded environments?


## Some comments - Ubuntu 18.04 LTS ##
* linux-generic-hwe-18.04 (5.4.0-58-generic)
* heimdal-clients do not support ccache type KEYRING
* heimdal-clients and heimdal-kcm do not work properly
  * problems with KRB5CCNAME
  * KDC time skew
```bash
[kulhanek@pes ~]$ export KRB5CCNAME=KCM:1001

[kulhanek@pes ~]$ kinit
kulhanek@META's Password:
[kulhanek@pes ~]$ klist
klist: krb5_cc_get_principal: No credentials cache file found

[kulhanek@pes ~]$ kinit -c KCM:1001
kulhanek@META's Password:
[kulhanek@pes ~]$ klist
Credentials cache: KCM:1001
        Principal: kulhanek@META

  Issued                Expires               Principal
Jan 14 20:56:51 2021  Jan 15 06:56:47 2021  krbtgt/META@META

[kulhanek@pes ~]$ klist -a
Credentials cache: KCM:1001
        Principal: kulhanek@META
    Cache version: 0
  KDC time offset: 5 years 3 months 3 weeks 5 days 19 hours 22 minutes 40 seconds

Server: krbtgt/META@META
Client: kulhanek@META
```
* krb5-user and heimdal-kcm seem to work with some minor problems
  * some tickets are not properly overwritten when ccache is copied
```bash
[kulhanek@pes ~]$ klist
Credentials cache: KCM:1001
        Principal: kulhanek@META

  Issued                Expires               Principal
Jan 14 20:19:50 2021  Jan 15 06:19:49 2021  afs/zcu.cz@ZCU.CZ
Jan 14 20:19:50 2021  Jan 15 06:19:49 2021  krbtgt/ZCU.CZ@META
Jan 14 20:19:49 2021  Jan 15 06:19:49 2021  afs/ics.muni.cz@ICS.MUNI.CZ
Jan 14 20:19:49 2021  Jan 15 06:19:49 2021  krbtgt/ICS.MUNI.CZ@META
Jan 14 20:19:49 2021  Jan 15 06:19:49 2021  krbtgt/META@META
Jan 14 21:08:07 2021  Jan 15 07:08:07 2021  krbtgt/META@META
```

## Related work ##
* [Heimdal](https://github.com/heimdal/heimdal)
* [kAFS](https://www.kernel.org/doc/html/latest/filesystems/afs.html)
* [kafs-client](https://www.infradead.org/~dhowells/kafs/kafs_client.html)
* [linux-pam](https://github.com/linux-pam/linux-pam)
* [pam-afs-session](https://www.eyrie.org/~eagle/software/pam-afs-session/)

