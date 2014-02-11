#include "settings.h"


#define USER_ADD 1
#define USER_DEL 2
#define USER_LIST 3


void PrintVersion()
{
printf("ParanoidTelnetD: version %s\n",VERSION);
exit(0);
}


void SettingsPrintUsage()
{
printf("ParanoidTelnetD: version %s\n",VERSION);
printf("Author: Colum Paget\n");
printf("Email: colums.projects@gmail.com\n");
printf("Blog: http://idratherhack.blogspot.com\n\n");

printf("ptelnetd (Paranoid Telnet Daemon) is a telnet server intended to be used with embedded or commodity hardware that communicates over telnet. ptelnetd has its own authentication system, so that usernames/passwords can be used that are unique to ptelnetd, and cannot be used to log into the main system. When used with this 'native' authentication ptelnetd cannot log in users against accounts that are not listed in it's authentication file, thus limiting logins to those usernames/passwords set up for use with ptelnetd, and potentially only with ptelentd. Ptelnetd supports two types of chroot jail, blacklisting/whitelisting of users, ip-addresses and mac-addresses, and many other features intended to make the insecure telnet protocol as secure as possible.\n\n");
printf("Usage: ptelnetd <options>\n");
printf("Options:\n");
printf("%-33s %s","-?","This help\n");
printf("%-33s %s","-help","This help\n");
printf("%-33s %s","--help","This help\n");
printf("%-33s %s","-version","Version info\n");
printf("%-33s %s","--version","Version info\n");
printf("%-33s %s","-p <port>","Port to run service on\n");
printf("%-33s %s","-port <port>","Port to run service on\n");
printf("%-33s %s","-pid-file <path>","Path to pid file. Can contain variables (See 'VARIABLES') below.\n");
printf("%-33s %s","-i <interface>","Restrict service to a particular network interface (eth0, eth1, etc).\n");
printf("%-33s %s","","Thus different ptelnetds with different configs can be set on different interfaces\n");
printf("%-33s %s","-D","Don't demonize/fork into background.\n");
printf("%-33s %s","-nodemon","Don't demonize/fork into background.\n");
printf("%-33s %s","-inetd","Run from inetd. Treat stdin/stdout as the network connection.\n");
printf("%-33s %s","","N.B. NOT ALL OPTIONS WILL WORK WITH THIS. See 'INETD' below.\n");
printf("%-33s %s","-A <auth methods>","Comma separated list of authentication methods. See 'AUTHENTICATION' below.\n");
printf("%-33s %s","-auth-methods <auth methods>","Comma separated list of authentication methods. See 'AUTHENTICATION' below.\n");
printf("%-33s %s","-a <path>","Path to native authentication file. See 'AUTHENTICATION' below.\n");
printf("%-33s %s","-auth-file <path>","Path to native authentication file. See 'AUTHENTICATION' below.\n");
printf("%-33s %s","-auth-tries <max value>","No of authentication attempts permitted before disconnect.\n");
printf("%-33s %s","-auth-delay <seconds>","Delay in seconds between authentication attempts.\n");
printf("%-33s %s","-allow <users>","Comma separated list of users allowed to log in.\n");
printf("%-33s %s","-allow-users <users>","Comma separated list of users allowed to log in.\n");
printf("%-33s %s","-deny <users>","Comma separated list of users denied log in.\n");
printf("%-33s %s","-deny-users <users>","Comma separated list of users denied log in.\n");
printf("%-33s %s","-allow-ips <ip addresses>","Comma separated list of hosts allowed log in.\n");
printf("%-33s %s","-deny-ips <ip addresses>","Comma separated list of hosts denied log in.\n");
printf("%-33s %s","-allow-macs <MAC addresses>","Comma separated list of ethernet MAC addresses allowed log in.\n");
printf("%-33s %s","-deny-macs <MAC addresses>","Comma separated list of ethernet MAC addresses denied log in.\n");
printf("%-33s %s","-local","only allow login to 'local' hosts (i.e. those hosts with an entry in the servers arp cache, and so on the same ethernet segment as the host\n");
printf("%-33s %s","-debug","Extra logging for debugging\n");
printf("%-33s %s","-error-log-level <syslog level>","syslog level (debug,info,notice,warn,error,crit) to use for error logging\n");
printf("%-33s %s","-info-log-level <syslog level>","syslog level (debug,info,notice,warn,error,crit) to use for informational logging\n");
printf("%-33s %s","-banner <text>","Text to display when a client connects. 'text' can contain variables. See 'VARIABLES' below.\n");
printf("%-33s %s","-chroot <directory>","Chroot into directory before doing anything else. 'directory' can contain variables. See 'VARIABLES' below.\n");
printf("%-33s %s","-dynhome <directory>","Dynamically generate home directories. 'directory' can contain variables. See 'VARIABLES' below.\n");
printf("%-33s %s","-chhome","After login chroot into the user's home directory.\n");
printf("%-33s %s","-env <environment variables>","Comma separated list of environment variables in 'name=value' format to be setup after user logs in.\n");
printf("%-33s %s","-shell <path>","program/shell to be run after user logs in.\nDefaults to /bin/sh, which is overridden by entries in /etc/passwd if system authentication is being used, which is overridden by this option if this option is active\n");
printf("%-33s %s","-real-user","User to run 'shell' as. This overrides anything set in the authentication files\n");
printf("%-33s %s","-login-script <path>","Script to run to set up user's environment. See 'LOGIN/LOGOUT SCRIPTS' below.\n");
printf("%-33s %s","-logout-script <path>","Script to run to clean up user's environment. See 'LOGIN/LOGOUT SCRIPTS' below.\n");
printf("%-33s %s","-m <dir list>","list of directories to 'bind mount' in user's home dir. See 'BIND MOUNTS' below\n");
printf("%-33s %s","-mounts <dir list>","list of directories to 'bind mount' in user's home dir. See 'BIND MOUNTS' below\n");
printf("%-33s %s","-honeypot","'Honeypot' mode. Fail to authenticate any user, even if they've got the right password, and log EVERYTHING as critical. See 'HONEYPOT MODE' below.\n");
printf("%-33s %s","-user add [-a <auth file> <username> <password> [-encrypt <encryption type>] [-home <home directory>] [-shell <shell>]","'Add a user to the config file. -encrypt sets the type of encryption used to protect the stored password. Default is 'sha1', other options are 'md5', 'sha256' and 'sha512'.\n");
printf("%-33s %s","-user del [-a <auth file> <username>","'Delete a user from the config file.\n");
printf("%-33s %s","-user list [-a <auth file>","List users in the config file.\n");

printf("\nAUTHENTICATION.\n\n");
printf("   ptelnetd can use a number of different authentication methods, which can be set with the '-auth-types' command line option. Available types are:\n\n");
printf("	native	The default method. Uses ptelnetd's native authentication file (specified with -auth-file, defaults to /etc/ptelnetd.auth) to authenticate.\n Available methods are:\n\n");
printf("	pam		Use Pluggable Authentication Modules.\n");
printf("	shadow	Authenticate against passwords in /etc/shadow.\n");
printf("	passwd	Authenticate against passwords in /etc/passwd.\n");
printf("	open	NO AUTHENTICATION. This method has certain restrictions.\n\n");
printf("    'open' authentication can only be used in combination with either -chroot or -chhome. Without some form of chroot jail, 'open' authentication would allow anyone to get a shell on your system without logging in, which would be a Bad Thing.\n\n");
printf("    'native' authentication is set up using the 'ptelnetd -user add/delete/list' commands. The default authentication file is /etc/ptelnetd, but this can be overridden with the '-auth-file' option.\n");
printf("    Most authentication methods can be used in combination by listing them as comma-separated values. The only exception is 'open', which must be specified on its own, or it will be ignored\n");

printf("\nUSERS and REAL USERS\n\n");
printf("   When using 'native' authentication, ptelentd uses it's own 'users scheme'. 'native' users are 'virtual' users that map to a 'real' user. For instance, there could be 'native' users called 'Tom', 'Dick' and 'Harriet', and they could all run as the real user 'nobody'. Ptelnetd searches for a suitable 'real user' at startup, checking for the existence of the 'nobody', 'guest' or 'daemon' accounts, and using the first one it finds. This behavior can be overridden with the '-real-user' option, which explicitly specifies the user to be used.\n");
printf("   When not using 'native' or 'open' authentication, the users are the real users specified in /etc/passwd. However, the '-real-user' command can still be used to switch them to some other user after they've authenticated.\n");

printf("\nVARIABLES.\n\n");
printf("   Some config options (for example 'banner') accept string arguments that may take variables. e.g.\n\n");
printf("	ptelnetd -banner 'Welcome to $(ServerHost) running on port $(ServerPort) of $(ServerIP)'\n\n");
printf("(Note use of single quotes to protect '$' from the shell).\n");
printf("Available variables are:\n\n");
printf("	%-20s %s\n","ClientHost","Hostname of the client");
printf("	%-20s %s\n","ClientIP","IP-Address of the client");
printf("	%-20s %s\n","ClientMAC","MAC-Address of the client");
printf("	%-20s %s\n","ServerHost","Hostname of the server");
printf("	%-20s %s\n","ServerIP","IP-Address of the server");
printf("	%-20s %s\n","ServerPort","Port that ptelnetd is running on");
printf("	%-20s %s\n","Interface","Interface that ptelnetd is bound to");
printf("	%-20s %s\n","User","User (available after authentication)");
printf("	%-20s %s\n","RealUser","Real User (i.e. unix system user). (Available after authentication)");
printf("	%-20s %s\n","Time","Time in %H:%M:%S format");
printf("	%-20s %s\n","Date","Date in %Y/%m/%d format");
printf("	%-20s %s\n","DateTime","Date and time in %Y/%m/%d %H:%M:%S format");
printf("\n	Variables can be used in the banner, in 'Dynamic home directory' paths, and in the pidfile path. 'ClientIP', 'ClientHost' and 'ClientMAC' are only available after a connection is made. 'User' and 'RealUser' are only available after login.\n");

printf("\nCHROOT AND CHHOME\n\n");
printf("	Paranoid TelnetD supports two types of chroot jail. 'ChHome' happens after login, and chroots the user's shell into their home directory. This means that the user sees themselves locked into their home directory, which is now their root directory. However, the user's connection is serviced by a helper process that exists outside of the chhome jail, so that when the user logs off the 'Logout script' can be run to take any files out of the chhome jail and import them into applications on the main system (see LOGIN/LOGOUT SCRIPTS below). In this mode authentication, login/logout scripting, bind mounts and dynamic home directories are all processed OUTSIDE of and BEFORE chhome.\n");
printf("	The other type of chroot is configured with the '-chroot <path>' command-line argument. This chroots the helper process and the shell into the specified directory. This means that everything that happens is locked into the chroot directory. This is intended for systems where there's an entire OS installation (a traditional chroot environment) that everything should be locked into. This has impacts on authentication, as all the authentication files must now be in the chroot directory; 'dynhome', because the dynamic home directory will be created relative to the chroot, 'Bind mounts', as the mounted directories will be relative to chroot, and 'login/logout scripts', as these scripts too must be installed in the chroot.\n");

printf("\nDYNHOME: DYNAMIC HOME DIRECTORIES\n\n");
printf("	Paranoid TelnetD supports on-the-fly home directory creation. By supplying variables in the path supplied as an argument to -dynhome one can specify a unique directory for a user or host or IP or mac, or any combination of these. This directory is created and used as the home directory after login. When the session ends, the directory should be deleted (this can fail if there are files left in the directory)\n");

printf("\nBIND MOUNTS\n\n");
printf("	The -mounts <directories> command-line option supplies a comma-separated list of directories to be 'bind mounted' under the user's home directory. This causes these directories to be seen as subdirectories under the user's home directory. This is particularly useful when used with 'chhome' as it allows a /lib /etc /bin directory to be supplied within the user's chrooted chroot directory, limiting what they have access to. By default the directories are mounted as copies of themselves, so '-mounts /lib,/bin,/etc would mount the directories as /lib, /bin and /etc UNDER THE USERS HOME DIRECTORY. However, the use of the syntax '<source dir>:<mount point> allows directories to be mounted in different places under the users home directory. e.g. '/usr/jail/lib:/lib,/usr/jail/bin:/bin' would mount /usr/jail/lib and /usr/jail/bin as /lib and /bin respectively. \n");

printf("\nLOGIN/LOGOUT SCRIPTS\n\n");
printf("   The '-login-script' and '-logout-script' options allow scripts to be run on login/logout respectively. These scripts are run *outside* of the 'chhome' style of chroot, allowing the login script to copy things into the user's chroot-jail, then the user is chrooted into it, and when their session ends the logout script can import/copy files from the jail to the larger system.\n\n");

printf("\nHONEYPOT MODE\n\n");
printf("	The '-honeypot' argument invokes a special mode in which Paranoid TelnetD will pretend to authenticate users, but will never accept any credentials as valid. It also logs everything as 'critical'. This provides a kind of poor-person's honeypot, as Paranoid TelnetD can be installed on systems that no-one should ever telnet into, and the logs watched for 'critical' error messages coming out of ptelnetd.\n");

printf("\nINETD\n\n");
printf("		If run out of inetd then obviously interface and port cannot be specified, nor will a pid file be created.\n");

printf("\nEXAMPLES\n\n");
printf("    %s\n          %s\n\n","ptelnetd -auth-methods pam -chhome","Allow users to log in 'for real' but jail them in their home directories");
printf("    %s\n          %s\n\n","ptelnetd -auth-methods pam -chhome -dynhome '/home/$(User)-$(ClientIP)'","Allow users to log in 'for real' but jail them in a dynamically created home directory\n");
printf("    %s\n          %s\n\n","		ptelnetd -real-user nobody -chhome -dynhome '/home/$(User)-$(ClientIP)'	-allow-ips 192.168.[2-3].*,10.0.0.[1-5]","Allow users to login against username/passwords in the native file (/etc/ptelnted.auth). All users will run as the real user 'nobody'. Each user will be jailed in a dynamically created directory. Only allow logins from ipranges 192.168.1.x and 192.168.3.x and 10.0.0.1 to 10.0.0.5\n");
printf("    %s\n          %s\n\n","		ptelnetd -auth-methods pam -allow-macs d0:b:bd:63:94:f1","Allow users to login as 'real users' using Pluggable Authentication Modules, but only from one mac address");
printf("    %s\n          %s\n\n","		ptelnetd -auth-methods open -chroot /home/mud -shell './mud-server'","ALLOW ANYONE IN WITHOUT AUTHENTICATION. Jail everything into /home/mud. Run the program 'mud-server' as the shell");

exit(0);
}



void SettingsInit()
{
//Default users that the system could run as
char *DefaultUsers[]={"nobody","daemon","guest","wwwrun",NULL};
int i;

memset(&Settings,0,sizeof(TSettings));
Settings.Interface=CopyStr(Settings.Interface,"");
Settings.Port=23;
Settings.AuthDelay=3;
Settings.AuthTries=3;
Settings.AuthMethods=CopyStr(Settings.AuthMethods,"native");
Settings.AuthFile=CopyStr(Settings.AuthFile,"/etc/ptelnetd.auth");
Settings.Shell=CopyStr(Settings.Shell,"/bin/sh");
Settings.LogPath=CopyStr(Settings.LogPath,"/var/log/telnetd.log");
Settings.BindMounts=CopyStr(Settings.BindMounts,"/bin/,/lib/,/usr/lib/");
Settings.BlockHosts=ListCreate();
for (i=0; DefaultUsers[i] !=NULL; i++)
{
			if (getpwnam(DefaultUsers[i]))
			{
				Settings.RealUser=CopyStr(Settings.RealUser,DefaultUsers[i]);
				break;
			}
}

Settings.ChDir=CopyStr(Settings.ChDir,"/tmp/");
}


void SettingsParseUserCommandLine(int argc, char *argv[])
{
int Type=0, i;
char *User=NULL, *Pass=NULL, *HomeDir=NULL, *Path=NULL, *RealUser=NULL, *Shell=NULL, *Encrypt=NULL;

Path=CopyStr(Path,Settings.AuthFile);
RealUser=CopyStr(RealUser,"nobody");
HomeDir=CopyStr(HomeDir,"");
Shell=CopyStr(Shell,"");
Encrypt=CopyStr(Encrypt,"sha1");

if (strcmp(argv[2],"add")==0) Type=USER_ADD;
else if (strcmp(argv[2],"del")==0) Type=USER_DEL;
else if (strcmp(argv[2],"list")==0) Type=USER_LIST;
else 
{
	printf("ERROR: 1st argument after '-user' must be 'add', 'del' or 'list'.\n");
	exit(1);
}

for (i=3; i < argc; i++)
{
	if (strcmp(argv[i],"-a")==0) Path=CopyStr(Path,argv[++i]);
	else if (strcmp(argv[i],"-f")==0) Path=CopyStr(Path,argv[++i]);
	else if (strcmp(argv[i],"-h")==0) HomeDir=CopyStr(HomeDir,argv[++i]);
	else if (strcmp(argv[i],"-e")==0) Encrypt=CopyStr(Encrypt,argv[++i]);
	else if (strcmp(argv[i],"-encrypt")==0) Encrypt=CopyStr(Encrypt,argv[++i]);
	else if (strcmp(argv[i],"-home")==0) HomeDir=CopyStr(HomeDir,argv[++i]);
	else if (strcmp(argv[i],"-shell")==0) Shell=CopyStr(Shell,argv[++i]);
	else if (*argv[i] != '-')
	{
		if (! StrLen(User)) User=CopyStr(User,argv[i]);
		else if (! StrLen(Pass)) Pass=CopyStr(Pass,argv[i]);
	}
}

if (Type==USER_ADD)
{
	if (! StrLen(User)) 
	{
		printf("ERROR: username missing\n");
		exit(1);
	}

	if (! StrLen(Pass)) 
	{
		printf("ERROR: password missing\n");
		exit(1);
	}
	UpdateNativeFile(Path, User, Encrypt, Pass, HomeDir, RealUser, Shell, "");
}
else if (Type==USER_LIST)
{
	ListNativeFile(Path);
}

DestroyString(User);
DestroyString(Pass);
DestroyString(Path);
DestroyString(Shell);
DestroyString(Encrypt);
DestroyString(HomeDir);
DestroyString(RealUser);
exit(0);
}



int SettingsParseLogLevel(char *LogLevel)
{
if (strcmp(LogLevel,"crit")==0) return(LOG_CRIT);
if (strcmp(LogLevel,"critical")==0) return(LOG_CRIT);
if (strcmp(LogLevel,"error")==0) return(LOG_ERR);
if (strcmp(LogLevel,"err")==0) return(LOG_ERR);
if (strcmp(LogLevel,"err")==0) return(LOG_ERR);
if (strcmp(LogLevel,"warn")==0) return(LOG_WARNING);
if (strcmp(LogLevel,"warning")==0) return(LOG_WARNING);
if (strcmp(LogLevel,"notice")==0) return(LOG_NOTICE);
if (strcmp(LogLevel,"debug")==0) return(LOG_DEBUG);

return(LOG_INFO);
}


void SettingsParseCommandLine(int argc, char *argv[])
{
int i;

if (strcmp("-user", argv[1])==0) SettingsParseUserCommandLine(argc, argv);
else
{
for (i=1; i < argc; i++)
{
	if (strcmp("-?",argv[i])==0) SettingsPrintUsage();
	else if (strcmp("-help",argv[i])==0) SettingsPrintUsage();
	else if (strcmp("--help",argv[i])==0) SettingsPrintUsage();
	else if (strcmp("-version",argv[i])==0) PrintVersion();
	else if (strcmp("--version",argv[i])==0) PrintVersion();
	else if (strcmp("-chroot",argv[i])==0) 
	{
		Settings.Flags |= FLAG_CHROOT;
		Settings.ChDir=CopyStr(Settings.ChDir,argv[++i]);
	}
	else if (strcmp("-dynhome",argv[i])==0) 
	{
		Settings.Flags |= FLAG_DYNHOME | FLAG_UNMOUNT;
		Settings.DynamicHomeDir=CopyStr(Settings.DynamicHomeDir,argv[++i]);
	}
	else if (strcmp("-debug", argv[i])==0) Settings.Flags |= FLAG_DEBUG;
	else if (strcmp("-honeypot", argv[i])==0) 
	{
			Settings.Flags |= FLAG_DENYAUTH;
			Settings.AuthMethods=CopyStr(Settings.AuthMethods,"");
			Settings.AuthFile=CopyStr(Settings.AuthFile,"");
			Settings.InfoLogLevel=LOG_CRIT;
			Settings.ErrorLogLevel=LOG_CRIT;
	}
	else if (strcmp("-chhome", argv[i])==0) Settings.Flags |= FLAG_CHHOME;
	else if (strcmp("-banner", argv[i])==0) Settings.Banner=CopyStr(Settings.Banner,argv[++i]);
	else if (strcmp("-env", argv[i])==0) Settings.Environment=CopyStr(Settings.Environment,argv[++i]);
	else if (strcmp("-a", argv[i])==0) Settings.AuthFile=CopyStr(Settings.AuthFile,argv[++i]);
	else if (strcmp("-A", argv[i])==0) Settings.AuthMethods=CopyStr(Settings.AuthMethods,argv[++i]);
	else if (strcmp("-auth-methods", argv[i])==0) Settings.AuthMethods=CopyStr(Settings.AuthMethods,argv[++i]);
	else if (strcmp("-auth-file", argv[i])==0) Settings.AuthFile=CopyStr(Settings.AuthFile,argv[++i]);
	else if (strcmp("-pid-file", argv[i])==0) Settings.PidFile=CopyStr(Settings.PidFile,argv[++i]);
	else if (strcmp("-auth-tries", argv[i])==0) Settings.AuthTries=atoi(argv[++i]);
	else if (strcmp("-auth-delay", argv[i])==0) Settings.AuthDelay=atoi(argv[++i]);
	else if (strcmp("-allow", argv[i])==0) Settings.AllowUsers=CopyStr(Settings.AllowUsers,argv[++i]);
	else if (strcmp("-deny", argv[i])==0) Settings.DenyUsers=CopyStr(Settings.DenyUsers,argv[++i]);
	else if (strcmp("-allow-users", argv[i])==0) Settings.AllowUsers=CopyStr(Settings.AllowUsers,argv[++i]);
	else if (strcmp("-deny-users", argv[i])==0) Settings.DenyUsers=CopyStr(Settings.DenyUsers,argv[++i]);
	else if (strcmp("-allow-ips", argv[i])==0) Settings.AllowIPs=CopyStr(Settings.AllowIPs,argv[++i]);
	else if (strcmp("-deny-ips", argv[i])==0) Settings.DenyIPs=CopyStr(Settings.DenyIPs,argv[++i]);
	else if (strcmp("-allow-macs", argv[i])==0) Settings.AllowMACs=CopyStr(Settings.AllowMACs,argv[++i]);
	else if (strcmp("-deny-macs", argv[i])==0) Settings.DenyMACs=CopyStr(Settings.DenyMACs,argv[++i]);
	else if (strcmp("-local", argv[i])==0) Settings.Flags |= FLAG_LOCALONLY;
	else if (strcmp("-m", argv[i])==0) Settings.BindMounts=CopyStr(Settings.BindMounts,argv[++i]);
	else if (strcmp("-mounts", argv[i])==0) Settings.BindMounts=CopyStr(Settings.BindMounts,argv[++i]);
	else if (strcmp("-i", argv[i])==0) Settings.Interface=CopyStr(Settings.Interface,argv[++i]);
	else if (strcmp("-p", argv[i])==0) Settings.Port=atoi(argv[++i]);
	else if (strcmp("-port", argv[i])==0) Settings.Port=atoi(argv[++i]);
	else if (strcmp("-inetd", argv[i])==0) Settings.Flags |= FLAG_INETD;
	else if (strcmp("-D", argv[i])==0) Settings.Flags |= FLAG_NODEMON;
	else if (strcmp("-nodemon", argv[i])==0) Settings.Flags |= FLAG_NODEMON;
	else if (strcmp("-shell", argv[i])==0)
	{
		Settings.Shell=CopyStr(Settings.Shell,argv[++i]);
		Settings.Flags |= FLAG_FORCE_SHELL;
	}
	else if (strcmp("-error-log-level", argv[i])==0) Settings.ErrorLogLevel=SettingsParseLogLevel(argv[++i]);
	else if (strcmp("-info-log-level", argv[i])==0) Settings.InfoLogLevel=SettingsParseLogLevel(argv[++i]);
	else if (strcmp("-shell", argv[i])==0) Settings.Shell=CopyStr(Settings.Shell,argv[++i]);
	else if (strcmp("-login-script", argv[i])==0) Settings.LoginScript=CopyStr(Settings.LoginScript,argv[++i]);
	else if (strcmp("-logout-script", argv[i])==0) Settings.LogoutScript=CopyStr(Settings.LogoutScript,argv[++i]);
	else if (strcmp("-real-user", argv[i])==0) 
	{
		i++;
		if (getpwnam(argv[i])) Settings.RealUser=CopyStr(Settings.RealUser,argv[i]);
		else
		{
			printf("ERROR: No such user: %s\n",argv[i]);
			exit(1);
		}
		Settings.Flags |= FLAG_FORCE_REALUSER;
	}
	else 
	{
			printf("ERROR: Unknown option '%s'\n",argv[i]);
			Settings.Flags |= FLAG_ERROR;
	}
}
}

if (Settings.Flags & FLAG_ERROR)
{
	printf("%s -? for help\n",argv[0]);
	exit(1);
}
}




int SettingsValid()
{
if (! StrLen(Settings.RealUser))
{
  printf("%s\n","ERROR: ParanoidTelnetD cannot find a user to run programs as. ParanoidTelnetD is too paranoid to run programs as root.");
  syslog(LOG_ERR,"%s","ERROR: ParanoidTelnetD cannot find a user to run programs as. ParanoidTelnetD is too paranoid to run programs as root.");
  return(FALSE);
}

if (strcmp(Settings.AuthMethods,"open")==0)
{
	if (! (Settings.Flags & (FLAG_CHROOT | FLAG_CHHOME)))
	{
		printf("%s\n","ERROR: ParanoidTelnetD is too paranoid to allow 'open' authentication type without 'chroot' or 'chhome'. This would give free access to your entire system without a password. ParanoidTelnetd thinks that you are a little naieve.");
		syslog(LOG_ERR,"%s\n","ERROR: ParanoidTelnetD is too paranoid to allow 'open' authentication type without 'chroot' or 'chhome'. This would give free access to your entire system without a password. ParanoidTelnetd thinks that you are a little naieve.");
	 return(FALSE);
	}
}

return(TRUE);
}





