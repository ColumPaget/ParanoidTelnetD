[![Build Status](https://travis-ci.com/ColumPaget/ParanoidTelnetD.svg?branch=master)](https://travis-ci.com/ColumPaget/ParanoidTelnetD)



# SYNOPSIS

ptelnetd (Paranoid Telnet Daemon) is a telnet server intended to be used with embedded or commodity hardware that communicates over telnet. ptelnetd has its own authentication system, so that usernames/passwords can be used that are unique to ptelnetd, and cannot be used to log into the main system. When used with this 'native' authentication ptelnetd cannot log in users against accounts that are not listed in it's authentication file, thus limiting logins to those usernames/passwords set up for use with ptelnetd, and potentially only with ptelentd. Ptelnetd supports two types of chroot jail; TLS/SSL encryption (port 992); blacklisting/whitelisting of users, ip-addresses and mac-addresses; and many other features intended to make the insecure telnet protocol as secure as possible.

On linux ptelnetd can authenticate against any combination of it's own auth file, the shadow and password files, or Pluggable Authentication Modules (PAM).
On freebsd ptelnetd has only been seen to work with it's own auth file (PAM may work, but has not yet been tested).

On linux ptelnetd can use the 'NO_NEW_PRIVS' feature to prevent privilege escalation using apps like 'sudo' or 'su', even if the user knows the 'su' password.


# AUTHOR

Author: Colum Paget
Email: colums.projects@gmail.com


# DISCLAIMER

This is free software. It comes with no guarentees and I take no responsiblity if it makes your computer explode or opens a portal to the demon dimensions, or does anything. It is released under the Gnu Public Licence version 3.


# USAGE 

	ptelnetd <options>

# OPTIONS

```
-?                                This help
-help                             This help
--help                            This help
-version                          Version info
--version                         Version info
-p <port>                         Port to run service on
-port <port>                      Port to run service on
-pid-file <path>                  Path to pid file. Can contain variables (See 'VARIABLES') below.
-i <interface>                    Restrict service to a particular network interface. Either address or interface (eth0, eth1, etc) for IPv4. Full scoped address for IPv6.
-D                                Don't demonize/fork into background.
-nodemon                          Don't demonize/fork into background.
-inetd                            Run from inetd. Treat stdin/stdout as the network connection.  N.B. NOT ALL OPTIONS WILL WORK WITH THIS. See 'INETD' below.
-A <auth methods>                 Comma separated list of authentication methods. See 'AUTHENTICATION' below.
-auth-methods <auth methods>      Comma separated list of authentication methods. See 'AUTHENTICATION' below.
-a <path>                         Path to native authentication file. See 'AUTHENTICATION' below.
-auth-file <path>                 Path to native authentication file. See 'AUTHENTICATION' below.
-auth-tries <max value>           No of authentication attempts permitted before disconnect.
-auth-delay <seconds>             Delay in seconds between authentication attempts.
-allow <users>                    Comma separated list of users allowed to log in.
-allow-users <users>              Comma separated list of users allowed to log in.
-deny <users>                     Comma separated list of users denied log in.
-deny-users <users>               Comma separated list of users denied log in.
-allow-ips <ip addresses>         Comma separated list of hosts allowed log in.
-deny-ips <ip addresses>          Comma separated list of hosts denied log in.
-allow-macs <MAC addresses>       Comma separated list of ethernet MAC addresses allowed log in.
-deny-macs <MAC addresses>        Comma separated list of ethernet MAC addresses denied log in.
-local                            only allow login to 'local' hosts (i.e. those hosts with an entry in the servers arp cache, and so on the same ethernet segment as the host
-tls-cert <path>                  path to tls/ssl certificate file. Setting this will enable TLS/SSL by default and also change the default port to 992
-tls-key  <path>                  path to tls/ssl key file. You must also supply a -tls-cert argument
-local                            only allow login to 'local' hosts (i.e. those hosts with an entry in the servers arp cache, and so on the same ethernet segment as the host
-non-root                         run server as a user other than root. 'Port' must be set to greater than 1024 and the authentication file must be readable by the current user. Virtual users will run as the current user within the default directory (/var/empty) unless they have home directories specified in the authentication file.
-debug                            Extra logging for debugging
-error-log-level <syslog level>   syslog level (debug,info,notice,warn,error,crit) to use for error logging
-info-log-level <syslog level>    syslog level (debug,info,notice,warn,error,crit) to use for informational logging
-banner <text>                    Text to display when a client connects. 'text' can contain variables. See 'VARIABLES' below.
-idle <seconds>                   Session idle timeout in seconds.
-chroot <directory>               Chroot into directory before doing anything else. 'directory' can contain variables. See 'VARIABLES' below.
-dynhome <directory>              Dynamically generate home directories. 'directory' can contain variables. See 'VARIABLES' below.
-chhome                           After login chroot into the user's home directory.
-env <environment variables>      Comma separated list of environment variables in 'name=value' format to be setup after user logs in.
-shell <path>                     program/shell to be run after user logs in.
Defaults to /bin/sh, which is overridden by entries in /etc/passwd if system authentication is being used, which is overridden by this option if this option is active
-real-user                        User to run 'shell' as. This overrides anything set in the authentication files
-login-script <path>              Script to run to set up user's environment. See 'LOGIN/LOGOUT SCRIPTS' below.
-logout-script <path>             Script to run to clean up user's environment. See 'LOGIN/LOGOUT SCRIPTS' below.
-nosu                             Prevent privilege escalation to root for any users.
-su <group name>                  Only users in specified group are allowed to switch user to root.
-m <dir list>                     list of directories to 'bind mount' in user's home dir. See 'BIND MOUNTS' below
-mounts <dir list>                list of directories to 'bind mount' in user's home dir. See 'BIND MOUNTS' below
-honeypot                         'Honeypot' mode. Fail to authenticate any user, even if they've got the right password, and log EVERYTHING as critical. See 'HONEYPOT MODE' below.
-user add [-a <auth file>] <username> <password> [-encrypt <encryption type>] [-real-user <username>] [-home <home directory>] [-shell <shell>] [-conf <conf>]                           Add a user to the ptelnetd auth file. See 'NATIVE AUTHENTICATION' below.
-user del [-a <auth file>] <username> 'Delete a user from the ptelnetd auth file.
-user list [-a <auth file>]       List users in the ptelnetd auth file.
```


# AUTHENTICATION

ptelnetd can use a number of different authentication methods, which can be set with the '-auth-types' command line option. Available types are: 

```
  native     The default method. Uses ptelnetd's native authentication file (specified with -auth-file, defaults to /etc/ptelnetd.auth) to authenticate.
  pam         Use Pluggable Authentication Modules.
  shadow      Authenticate against passwords in /etc/shadow.
  passwd      Authenticate against passwords in /etc/passwd.
  cr-md5      Challenge/Response using native file passwords and md5 hashing.
  cr-sha1     Challenge/Response using native file passwords and sha1 hashing.
  cr-sha256   Challenge/Response using native file passwords and sha256 hashing.
  cr-sha512   Challenge/Response using native file passwords and sha512 hashing.
  pam-account Authenticate by any means, but check if PAM thinks the account is allowed/valid.
  open        NO AUTHENTICATION. This method has certain restrictions.
```

'open' authentication can only be used in combination with either -chroot or -chhome. Without some form of chroot jail, 'open' authentication would allow anyone to get a shell on your system without logging in, which would be a Bad Thing.

'native' authentication is set up using the 'ptelnetd -user add/delete/list' commands. The default authentication file is /etc/ptelnetd, but this can be overridden with the '-auth-file' option.

'pam-account' doesn't authenticate, instead authentication is performed by other means, and pam-account then checks if PAM thinks the account is allowed to log in, even if it authenticated. This might be used if a .nologin flag was set, or if a user is only allowed to log in from certain hosts, or at certain times of day.

'cr-md5', 'cr-sha1', 'cr-sha256', 'cr-sha512'. These are challenge-response authentication types. They require a password stored in PLAINTEXT in the native authentication file. When any of these authentication types are active the ptelnetd server sends a 'Challenge' string on the line before the 'login' prompt. The user authenticates by concatanating their password to the Challenge string (seperated by a colon) and then hashing the entire resulting string with the specified hash function. They submit this hashed string at the hash prompt. These hash strings can be created using utilites like 'md5sum' or 'sha512sum' by doing: 'echo -n 4+SiluCNxtX/CfM1jGnnK2JiunOnwnlz:MyPassword | md5sum' Where the long string before the colon is the Challenge obtained from the server, and 'MyPassword' is the users password.

Most authentication methods can be used in combination by listing them as comma-separated values. The only exception is 'open', which must be specified on its own, or it will be ignored


# NATIVE AUTHENTICATION

Users can be added to, deleted from, and listed from the 'ptelnetd auth file'. This is a file that holds details of 'virtual users' that ptelnetd knows about. By default this file is at `/etc/ptelnetd.auth` but it's location can be specified using the `-a` command-line option.

Users can be added with:

```
ptelnetd -user add [-a <auth file>] <username> <password> [-encrypt <encryption type>] [-real-user <username>] [-home <home directory>] [-shell <shell>] [-conf <conf>]
```

This will be a 'virtual user' that only exists for ptelnetd, so it will need to 'map' to a 'real user' (default is 'nobody').

`-encrypt` sets the type of encryption used to protect the stored password. Default encryption is 'sha1', other options are 'plain', 'md5', 'sha256' and 'sha512'. 

`-home` allows specifying a home-directory for this virtual user.

`-shell` allows specifying a shell, or other program, that the user runs on login.

`-real-user` allows specifying the 'real user' (default 'nobody') that this 'virutal user' runs as.  

`-conf` allows specifying user settings , see 'USER SETTINGS' below



# USERS and REAL USERS

When using 'native' authentication, ptelentd uses it's own 'users scheme'. 'native' users are 'virtual' users that map to a 'real' user. For instance, there could be 'native' users called 'Tom', 'Dick' and 'Harriet', and they could all run as the real user 'nobody'. Ptelnetd searches for a suitable 'real user' at startup, checking for the existence of the 'nobody', 'guest' or 'daemon' accounts, and using the first one it finds. This behavior can be overridden with the '-real-user' option, which explicitly specifies the user to be used.

Virtual users only exist for 'native' authentication. Thus, when not using 'native' or 'open' authentication, any 'users' must be the real users specified in /etc/passwd. However, the '-real-user' command can still be used to switch them to some other user after they've authenticated.



# VARIABLES.

Some config options (for example 'banner') accept string arguments that may take variables. e.g.

```
	ptelnetd -banner 'Welcome to $(ServerHost) running on port $(ServerPort) of $(ServerIP)'
```

(Note use of single quotes to protect '$' from the shell).
Available variables are:

```
	ClientHost           Hostname of the client
	ClientIP             IP-Address of the client
	ClientMAC            MAC-Address of the client
	ServerHost           Hostname of the server
	ServerIP             IP-Address of the server
	ServerPort           Port that ptelnetd is running on
	Interface            Interface that ptelnetd is bound to
	User                 User (available after authentication)
	RealUser             Real User (i.e. unix system user). (Available after authentication)
	Time                 Time in %H:%M:%S format
	Date                 Date in %Y/%m/%d format
	DateTime             Date and time in %Y/%m/%d %H:%M:%S format
```

Variables can be used in the banner, in 'Dynamic home directory' paths, and in the pidfile path. 'ClientIP', 'ClientHost' and 'ClientMAC' are only available after a connection is made. 'User' and 'RealUser' are only available after login.



# CHROOT AND CHHOME

Paranoid TelnetD supports two types of chroot jail. 'ChHome' happens after login, and chroots the user's shell into their home directory. This means that the user sees themselves locked into their home directory, which is now their root directory. However, the user's connection is serviced by a helper process that exists outside of the chhome jail, so that when the user logs off the 'Logout script' can be run to take any files out of the chhome jail and import them into applications on the main system (see LOGIN/LOGOUT SCRIPTS below). In this mode authentication, login/logout scripting, bind mounts and dynamic home directories are all processed OUTSIDE of and BEFORE chhome.

The other type of chroot is configured with the '-chroot <path>' command-line argument. This chroots the helper process and the shell into the specified directory. This means that everything that happens is locked into the chroot directory. This is intended for systems where there's an entire OS installation (a traditional chroot environment) that everything should be locked into. This has impacts on authentication, as all the authentication files must now be in the chroot directory; 'dynhome', because the dynamic home directory will be created relative to the chroot, 'Bind mounts', as the mounted directories will be relative to chroot, and 'login/logout scripts', as these scripts too must be installed in the chroot.

Chroot can also be set on a per user basis when using 'native' authentication with the 'ptelnetd user -add' command, and where supported more advanced types of containment like linux containers can be activated. See 'USER SETTINGS' below for more details.



# DYNHOME: DYNAMIC HOME DIRECTORIES

Paranoid TelnetD supports on-the-fly home directory creation. By supplying variables in the path supplied as an argument to -dynhome one can specify a unique directory for a user or host or IP or mac, or any combination of these. This directory is created and used as the home directory after login. When the session ends, the directory should be deleted (this can fail if there are files left in the directory)



# BIND MOUNTS

The -mounts <directories> command-line option supplies a comma-separated list of directories to be 'bind mounted' under the user's home directory. This causes these directories to be seen as subdirectories under the user's home directory. This is particularly useful when used with 'chhome' as it allows a /lib /etc /bin directory to be supplied within the user's chrooted chroot directory, limiting what they have access to. By default the directories are mounted as copies of themselves, so '-mounts /lib,/bin,/etc would mount the directories as /lib, /bin and /etc UNDER THE USERS HOME DIRECTORY. However, the use of the syntax '<source dir>:<mount point> allows directories to be mounted in different places under the users home directory. e.g. '/usr/jail/lib:/lib,/usr/jail/bin:/bin' would mount /usr/jail/lib and /usr/jail/bin as /lib and /bin respectively. 



# LOGIN/LOGOUT SCRIPTS

The '-login-script' and '-logout-script' options allow scripts to be run on login/logout respectively. These scripts are run *outside* of the 'chhome' style of chroot, allowing the login script to copy things into the user's chroot-jail, then the user is chrooted into it, and when their session ends the logout script can import/copy files from the jail to the larger system.


# USER SETTINGS

When using 'native' authentication various configurations can be setup against a particular username/password combination. These can be set using the 'ptelnetd -user add -conf' method or, if brave, by editing the .auth file's last field. Configuration options are a space separated list of:

```
chroot=<path>    chroot session into <path>
nice=value       'nice' value of session
prio=value       scheduling priority of session (equivalent to 0 - nice value)
priority=value   scheduling priority of session (equivalent to 0 - nice value)
mem=value        resource limit for memory (data segment) in session
fsize=value      resource limit for filesize in session
files=value      resource limit for open files in session
coredumps=value  resource limit for max size of coredump files in session
procs=value      resource limit for max number of processes ON A PER USER BASIS.
nosu             LINUX ONLY: prevent switching user to root. This requires kernel support and must be built-in at compile time.
ns=<path>        linux namespace to join. <path> is either a path to a namespace file, or a path to a directory (e.g. /proc/<pid>/ns ) that contains namespace descriptor files
container        this uses linux containers (if supported). It creates a new directory, mounts read-only copies of /bin /lib /usr/lib in it, chroots into it, switches to a new namespace for network (which disallows all network access), IPC, processes, and uname values. This results in a session that sees no network, no other processes on the system (except for a local 'init' that serves the session) no IPC, and which only has read-only access to a few directories, and write access only to the temporary directory it's living in.
+net             When used in combination with 'container' this allows the container to have normal network access, all other restrictions still apply


```

Please note: when using 'container' all your needed libraries must be in /lib or /usr/lib and you'll probably need an /etc/termcap file for the terminal to work correctly.
	

# HONEYPOT MODE

The '-honeypot' argument invokes a special mode in which Paranoid TelnetD will pretend to authenticate users, but will never accept any credentials as valid. It also logs everything as 'critical'. This provides a kind of poor-person's honeypot, as Paranoid TelnetD can be installed on systems that no-one should ever telnet into, and the logs watched for 'critical' error messages coming out of ptelnetd.



# INETD

If run out of inetd then obviously interface and port cannot be specified, nor will a pid file be created.



# IPv6

IPv6 support is disabled in the default build, but can be built in with 'configure --enable-ip6'. If you compile ptelnetd with IPv6, and then run ptelnetd without a specified interface, then both IPv4 and IPv6 will work. If you specify an interface then, if you specify it by interface name, or by an IPv4 address, only IPv4 will work, whereas if you specify and IPv6 address, only IPv6 will work.  Thus if you want to run both IPv4 and IPv6 on a specific interface, you'll have to launch two ptelnetd processes, one bound to the IPv4 address and one to the IPv6.

# TLS/SSL

TLS/SSL support is disabled in the default build, but can be built with 'configure --enable-ssl'. With SSL support enabled the command-line options -tls-cert and -tls-keyfile can be used to set the certificate and key file for tls, at which point the default port becomes 992 instead of 23 and the connection is encrypted by default.

# EXAMPLES

```
    ptelnetd -auth-methods pam -chhome
          Allow users to log in 'for real' but jail them in their home directories

    ptelnetd -auth-methods pam -chhome -dynhome '/home/$(User)-$(ClientIP)'
          Allow users to log in 'for real' but jail them in a dynamically created home directory


    ptelnetd -real-user nobody -chhome -dynhome '/home/$(User)-$(ClientIP)'	-allow-ips 192.168.[2-3].*,10.0.0.[1-5]
          Allow users to login against username/passwords in the native file (/etc/ptelnted.auth). All users will run as the real user 'nobody'. Each user will be jailed in a dynamically created directory. Only allow logins from ipranges 192.168.1.x and 192.168.3.x and 10.0.0.1 to 10.0.0.5


    ptelnetd -auth-methods pam -allow-macs d0:b:bd:63:94:f1
          Allow users to login as 'real users' using Pluggable Authentication Modules, but only from one mac address

    ptelnetd -auth-methods open -chroot /home/mud -shell './mud-server'
          ALLOW ANYONE IN WITHOUT AUTHENTICATION. Jail everything into /home/mud. Run the program 'mud-server' as the shell
```
