# kAFS-user #
This package provides user space commands for setup and use of kAFS (kernel AFS). 

## Installation ##
1) Install the necessary dependencies:
```bash
Heimdal Krb5:
$ sudo apt-get install heimdal-multidev libpam0g-dev libkeyutils-dev

MIT Krb5:
$ sudo apt-get install krb5-multidev libpam0g-dev libkeyutils-dev
```

2) Download the source code. Update CMakeList.txt if necessary, then compile and install the code.
```bash
$ git clone https://github.com/kulhanek/kafs-user.git
$ cd kafs-user
$ cmake .
$ make
$ sudo make install
```

## Setup AFS ##
1) Configure CellServDB, TheseCells, and ThisCell files in the /etc/kafs-user/ directory. Their meaning and syntax
is the same as for OpenAFS. Configuration using AFSDB DNS is not supported.

2) Enable the afs.mount unit for its automatic start at boot.
```bash
$ sudo systemctl enable afs.mount
```

3) Or mount it manually.
```bash
$ sudo systemctl start afs.mount
```

## AFS Token Manipulation ##
AFS tokens can be manipulated with the following commands:

* kinit.kafs - create new TGT ticket and possibly AFS tokens as well
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

locpag_for_pam, locpag_for_user, locpag_for_principal are specified as fnmatch() extended pattern.

The configuration can be changed using /etc/krb5.conf.
```bash
[libdefaults]
    default_ccache_name = KEYRING:persistent

[appdefaults]
    pam = {
        ccache = KEYRING:persistent
    }
    pam-kafs-session = {
        shared_pag  = true
        convert_cc_to = KEYRING
        locpag_for_user = +(admin|manager)
    }
```

## Some comments - Ubuntu 18.04 LTS ##
* linux-generic-hwe-18.04 (5.4.0-58-generic)
* heimdal-clients does not support ccache type KEYRING
* heimdal-clients and heimdal-kcm does not work properly
** problems with KRB5CCNAME
** KDC time skew

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
* krb5-user and heimdal-kcm seems to work with some minor problems
** some tickets are not properly overwritten when ccache is copied
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
* openssh does not honor default_ccache_name
** ccache is hardcoded and resolve to FILE type with random name
** [reported](https://bugs.launchpad.net/ubuntu/+source/openssh/+bug/1889548)

## Solution ##
* use krb5-user with KEYRING (default_ccache_name = KEYRING:persistent)
* pam_krb5 with KEYRING (ccache = KEYRING:persistent)
* pam_kafs_session with convert_cc_to = KEYRING to overcome openssh hardcoded ccache name
* both Kerberos tickets and AFS tokens are stored in the same session keyring
* this session keyring can be shared between multiple logins if shared_pag  = true is set for pam_kafs_session


## Related work ##
* [Heimdal](https://github.com/heimdal/heimdal)
* [kAFS](https://www.kernel.org/doc/html/latest/filesystems/afs.html)
* [kafs-client](https://www.infradead.org/~dhowells/kafs/kafs_client.html)
* [linux-pam](https://github.com/linux-pam/linux-pam)
* [pam-afs-session](https://www.eyrie.org/~eagle/software/pam-afs-session/)

