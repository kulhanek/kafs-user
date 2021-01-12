# kAFS-user #
This package provides user space commands for setup and use of kAFS (kernel AFS). 

## Installation ##
1. At this moment, the package requires Heimdal version of krb5. First, install the necessary dependencies:
```bash
$ sudo apt-get install heimdal-multidev libkeyutils-dev
```
1. Download the source code and update CMakeList.txt if necessary. Then, compile and install the code.
```bash
$ cmake .
$ make
$ sudo make install
```

## Setup AFS ##
1. Configure CellServDB, TheseCells, and ThisCell files in the /etc/kafs-user/ directory. Their meaning and syntax
is the same as for OpenAFS.
1. Enable the afs.mount unit for its automatic start at boot.
```bash
$ sudo systemctl enable afs.mount
```
1. Or mount it manually.
```bash
$ sudo systemctl start afs.mount
```

## AFS Token Manipulation ##
AFS tokens can be manipulated with the following commands:
* kinit.kafs - create new TGT ticket and possibly AFS tokens as well
* afslog.kafs - create AFS tokens if valid TGT ticket is available
* tokens.kafs - list AFS tokens and their expiration times
* unlog.kafs - destroy AFS tokens
* pagsh.kafs - create local or shared PAG (Process Authotrization Goup) and run a command or shell within it

## PAG ##
The PAG in the kAFS-user implementation is nothing else than a session keyring. Two types of PAGs are supported:
* local PAG
* shared PAG
The local PAG is a unique session keyring available for each login session. On contrary, the shared PAG
is represented by one named session keyring, which is shared among multiple login sessions.

## pam-kafs-session ##
This is a PAM module, which provides auth and session management tasks. The configuration is hardcoded
in the local.c file. By default, minium_uid is 1000 and support for shared PAGs is enabled. Defaults AFS cells
are taken from the TheseCells and ThisCell file.

