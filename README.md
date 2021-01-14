# kAFS-user #
This package provides user space commands for setup and use of kAFS (kernel AFS). 

## Installation ##
1) At this moment, the package requires Heimdal version of krb5. First, install the necessary dependencies:
```bash
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
* create_pag - create local/shared PAGs (yes) or keep default session keyring possibly created by pam_keyinit (no) (default: yes)
* create_tokens - create AFS tokens (default: yes)
* minimum_uid - minimum uid for which AFS tokens should be created (default: 1000)
* shared_pag - create shared PAG (default: no)
* locpag_for_pam - use local PAG for given PAM service module (default: NULL)
* locpag_for_user - use local PAG for given target user name (default: NULL)
* locpag_for_principal  - use local PAG for ccache default principal (default: NULL)

locpag_for_pam, locpag_for_user, locpag_for_principal are specified as fnmatch() extended pattern.

The configuration can be changed using /etc/krb5.conf.
```bash
[appdefaults]
    pam-kafs-session = {
        shared_pag  = true
        minimum_uid = 1000
    }
```


## Related work ##
* [Heimdal](https://github.com/heimdal/heimdal)
* [kAFS](https://www.kernel.org/doc/html/latest/filesystems/afs.html)
* [kafs-client](https://www.infradead.org/~dhowells/kafs/kafs_client.html)
* [linux-pam](https://github.com/linux-pam/linux-pam)
* [pam-afs-session](https://www.eyrie.org/~eagle/software/pam-afs-session/)

