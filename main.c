#include "common.h"
#include "Authenticate.h"
#include "telnet-protocol.h"
#include "settings.h"
#include <sys/mount.h>
#include <pwd.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fnmatch.h>
#define _GNU_SOURCE 
#include <unistd.h>


#define USER_ADD 1
#define USER_DEL 2
#define USER_LIST 3

//Older linux systems will lack 'lazy unmounts' (MNT_DETACH)
//so catch this and handle it here
#ifndef MNT_DETACH
#define MNT_DETACH 0
#endif

int g_argc;
char **g_argv;
int PidFile;
TSession *Session=NULL;

char *SessionSubstituteVars(char *RetStr, char *Format, TSession *Session)
{
ListNode *Vars;
char *Tempstr=NULL;

Tempstr=CopyStr(RetStr,"");
Vars=ListCreate();

Tempstr=SetStrLen(Tempstr,4096);
gethostname(Tempstr, 4096);
SetVar(Vars,"ServerHost",Tempstr);
Tempstr=FormatStr(Tempstr,"%d",Settings.Port);
SetVar(Vars,"ServerPort",Tempstr);
SetVar(Vars,"Interface",Settings.Interface);
SetVar(Vars,"Date",GetDateStr("%Y/%m/%d",NULL));
SetVar(Vars,"Date",GetDateStr("%H:%M:%S",NULL));
SetVar(Vars,"DateTime",GetDateStr("%Y/%m/%d %H:%M:%S",NULL));


//This function might be called before session setup, where all
//that we can substitute are 'interface' and 'serverhost/port' etc
if (Session)
{
	SetVar(Vars,"ClientHost",Session->ClientHost);
	SetVar(Vars,"ClientIP",Session->ClientIP);
	SetVar(Vars,"ClientMAC",Session->ClientMAC);
	SetVar(Vars,"ServerIP",Session->ServerIP);
	SetVar(Vars,"User",Session->User);
	SetVar(Vars,"RealUser",Session->RealUser);
}

Tempstr=SubstituteVarsInString(Tempstr,Format,Vars,0);

ListDestroy(Vars,Destroy);

return(Tempstr);
}


int Login(TSession *Session)
{
char *Tempstr=NULL;
int result, RetVal=FALSE;
time_t Duration, Start, Now, LastActivity;


Session->User=CopyStr(Session->User,NULL);
Session->Password=CopyStr(Session->Password,NULL);

//Clear out any crap
Tempstr=SetStrLen(Tempstr,4096);
result=TelnetReadBytes(Session->S, Tempstr, 4096, TNRB_ECHO | TNRB_NOPTY | TNRB_NONBLOCK);

while (StrValid(Session->User)==0)
{
  time(&LastActivity);

  if (Settings.IdleTimeout > 0) STREAMSetTimeout(Session->S, Settings.IdleTimeout);

	if (Settings.Flags & FLAG_CHALLENGE)
	{
		Session->Challenge=GenerateSalt(Session->Challenge, 24);
		Tempstr=MCopyStr(Tempstr, "Challenge/Response String: ", Session->Challenge, "\r\n", NULL); 
		STREAMWriteLine(Tempstr, Session->S); 
	}


	STREAMWriteLine("login: ", Session->S); STREAMFlush(Session->S);
	result=TelnetReadBytes(Session->S, Tempstr, 4096, TNRB_ECHO | TNRB_NOPTY);
	if (result > 0)
	{
		Session->User=CopyStrLen(Session->User, Tempstr, result);
		StripTrailingWhitespace(Session->User);
	}

  time(&Now);
  if ((Settings.IdleTimeout > 0) && ((Now - LastActivity) > Settings.IdleTimeout)) break;

}

STREAMWriteLine("Password: ", Session->S); STREAMFlush(Session->S);
result=TelnetReadBytes(Session->S, Tempstr, 4096, TNRB_NOPTY);
if (result > 0)
{
	Session->Password=CopyStrLen(Session->Password, Tempstr, result);
	StripTrailingWhitespace(Session->Password);
}

STREAMWriteLine("\r\n",Session->S);

if (Settings.Flags & FLAG_LOGCREDS) syslog(Settings.ErrorLogLevel,"%s@%s creds: user=%s pass=%s",Session->User,Session->ClientIP,Session->User,Session->Password);


if ((Settings.Flags & FLAG_LOCALONLY) && (! StrValid(Session->ClientMAC)))
{
	syslog(Settings.ErrorLogLevel,"%s@%s NOT LOCAL. Denying Login.",Session->User,Session->ClientIP);
}
else if (Settings.Flags & FLAG_HONEYPOT) syslog(Settings.ErrorLogLevel,"%s@%s login denied (honeypot mode)",Session->User,Session->ClientIP);
else if (
					(! (Session->Flags & FLAG_DENYAUTH)) &&
					(Authenticate(Session))
)  RetVal=TRUE; 

//Now that we've used the password, blank it from memory!
result=StrLen(Session->Password);
if (result > 0) memset(Session->Password,0,result);


Destroy(Tempstr);
//STREAMDisassociateFromFD(S);

return(RetVal);
}




void RmDirPath(char *path)
{
char *Tempstr=NULL, *ptr;

ptr=path;
while (*ptr=='/') ptr++;
Tempstr=CopyStr(Tempstr,ptr);

ptr=strrchr(Tempstr,'/');
while (ptr)
{
	rmdir(Tempstr);
	*ptr='\0';
	ptr=strrchr(Tempstr,'/');
}
if (StrValid(Tempstr)) rmdir(Tempstr);

Destroy(Tempstr);
}




void SetWindowSize(TSession *Session)
{
struct winsize w;

if (Session->TermWidth && Session->TermHeight) 
{
		memset(&w, 0, sizeof(struct winsize));
		w.ws_col=Session->TermWidth;
		w.ws_row=Session->TermHeight;
    ioctl(Session->S->in_fd, TIOCSWINSZ, &w);
}

Session->Flags &= (~FLAG_WINSIZE);
}


void SetupEnvironment(TSession *Session)
{
char *Token=NULL, *dptr;
const char *ptr;

setenv("LD_LIBRARY_PATH","/usr/local/lib:/usr/lib:/lib",1);
setenv("HOME",Session->HomeDir,TRUE);
if (StrValid(Session->TermType)) setenv("TERM",Session->TermType,TRUE);

SetWindowSize(Session);

ptr=GetToken(Settings.Environment,",",&Token,GETTOKEN_QUOTES);
while (ptr)
{
	dptr=strchr(Token,'=');
	if (dptr)
	{
		*dptr='\0';
		dptr++;
	}
	else dptr="";
	setenv(Token, dptr, TRUE);
	ptr=GetToken(ptr,",",&Token,GETTOKEN_QUOTES);
}

Destroy(Token);
}



//flags is not used by this function
int LaunchPtyFunc(void *p_Session, int Flags)
{
char *Tempstr=NULL;
int wid, len;
void *p_Lua=NULL;

Session=(TSession *) p_Session;
Session->S=STREAMFromDualFD(0,1);

SetupEnvironment(Session);

Tempstr=MCopyStr(Tempstr,"user=",Session->RealUser," ", Settings.ProcessConfig," ",Session->ProcessConfig,NULL);

ProcessApplyConfig(Tempstr);
Destroy(Tempstr);

return(execl(Session->Shell,Session->Shell,NULL));
}



//Every telnet session has two processes. One is the 'shell' or program that is being 
//accessed via telnet. Then there is one that reads data from the telnet socket, 
//strips/interprets it, and feeds the results to the 'shell'.
//This function is the latter process, it launches the shell in 'LaunchPtyFunc'.

void RunTelnetSession(TSession *Session)
{
STREAM *Local, *S;
char *Tempstr=NULL;
int result, fd;
ListNode *Streams;
struct passwd *pwent;
struct group *grent;
struct timeval tv;
time_t Duration, Start, Now, LastActivity;

time(&Start);
LastActivity=Start;
Streams=ListCreate();
ListAddItem(Streams,Session->S);

//if '-real-user' was specified on the command-line, then this overrides
//anything read from password files
if (Settings.Flags & FLAG_FORCE_REALUSER)
{
	Session->RealUser=CopyStr(Session->RealUser,Settings.RealUser);
}

//Get User Details before we chroot! 
if (StrValid(Session->RealUser))
{
    pwent=getpwnam(Session->RealUser);
		if (! pwent)
		{
			syslog(Settings.InfoLogLevel,"Failed to lookup RealUser '%s' for user '%s'",Session->RealUser,Session->User);
			exit(1);
		}
}


//if '-shell' was specified on the command-line, then this overrides
//anything read from password files
if (Settings.Flags & FLAG_FORCE_SHELL)
{
	Session->Shell=CopyStr(Session->Shell,Settings.RealUser);
}


if (Settings.Flags & FLAG_DYNHOME)
{
	Session->HomeDir=SessionSubstituteVars(Session->HomeDir,Settings.DynamicHomeDir,Session);
	Session->HomeDir=SlashTerminateDirectoryPath(Session->HomeDir);
	MakeDirPath(Session->HomeDir,0777);
}

//CD to the user's home directory
if (StrValid(Session->HomeDir)) 
{
	chdir(Session->HomeDir);
}

//This login script allows setting up any aspects of the environment before we launch the shell. For instance it 
//might be used to copy files into the chroot environment before chrooting
if (StrValid(Settings.LoginScript)) system(Settings.LoginScript);


//LAUNCH THE SHELL FUNCTION!!! This launches the program that the telnet user is 'speaking' to.
//If chhome is active, then it will be chrooted into the user's home directory

PseudoTTYSpawnFunction(&fd, LaunchPtyFunc, Session,  TTYFLAG_CANON | TTYFLAG_ECHO | TTYFLAG_IN_CRLF | TTYFLAG_OUT_CRLF | TTYFLAG_IGNSIG,  "");
Local=STREAMFromFD(fd);
STREAMSetTimeout(Local,0);

ListAddItem(Streams,Local);


Tempstr=SetStrLen(Tempstr,4096);
while (1)
{
	if (Settings.IdleTimeout) tv.tv_sec=Settings.IdleTimeout;
	else tv.tv_sec=3600 * 24;
	tv.tv_usec=0;

  S=STREAMSelect(Streams,&tv);
	time(&Now);
  if (S)
  {
    if (S==Session->S)
		{
			result=TelnetReadBytes(Session->S, Tempstr, 4096, TNRB_NONBLOCK);
			if (result ==-1) break;
			STREAMWriteBytes(Local,Tempstr,result);
		}
    else 
		{
			result=STREAMReadBytes(Local,Tempstr,4096);
			if (result < 0) break;
			STREAMWriteBytes(Session->S,Tempstr,result);

    if (result < 0) break;
		}
		if (Settings.Flags & FLAG_WINSIZE) SetWindowSize(Session);
		LastActivity=Now;
  }

	
	if ((Settings.IdleTimeout > 0) && ((Now - LastActivity) > Settings.IdleTimeout)) break;
}

if (StrValid(Settings.LogoutScript)) system(Settings.LogoutScript);
if (Settings.Flags & FLAG_DYNHOME) rmdir(Session->HomeDir);

Duration=time(NULL) - Start;
syslog(Settings.InfoLogLevel,"%s@%s logged out after %d secs",Session->User,Session->ClientIP, Duration);

STREAMClose(Local);
Destroy(Tempstr);
}


void GetClientHardwareAddress(TSession *Session)
{
STREAM *S;
char *Tempstr=NULL, *Token=NULL;
const char *ptr;

S=STREAMOpen("/proc/net/arp","r");
if (S)
{
	Tempstr=STREAMReadLine(Tempstr,S);
	Tempstr=STREAMReadLine(Tempstr,S);
	while (Tempstr)
	{
		ptr=GetToken(Tempstr,"\\S",&Token,0);
		if (strcmp(Token,Session->ClientIP)==0)
		{
		//HW Type
		ptr=GetToken(ptr,"\\S",&Token,0);
		//Flags
		ptr=GetToken(ptr,"\\S",&Token,0);

		//MAC
		ptr=GetToken(ptr,"\\S",&Session->ClientMAC,0);
			
		}
	Tempstr=STREAMReadLine(Tempstr,S);
	}
	STREAMClose(S);
}

Destroy(Tempstr);
Destroy(Token);
}


int FnmatchInList(char *List, char *Item)
{
char *Token=NULL;
const char *ptr;
int RetVal=FALSE;

if (! StrValid(Item)) return(FALSE);
ptr=GetToken(List,",",&Token,0);
while (ptr)
{
	if (fnmatch(Token,Item,0)==0) 
	{
	RetVal=TRUE;
	break;
	}
	ptr=GetToken(ptr,",",&Token,0);
}

Destroy(Token);
return(RetVal);
}



int CheckClientPermissions(TSession *Session)
{
int RetVal=TRUE;


if (StrValid(Settings.AllowIPs) || StrValid(Settings.AllowMACs)) RetVal=FALSE;


if (StrValid(Settings.AllowIPs))
{
	if (FnmatchInList(Settings.AllowIPs, Session->ClientIP)) RetVal=TRUE;
}

if (StrValid(Settings.DenyIPs))
{
	if (FnmatchInList(Settings.DenyIPs, Session->ClientIP)) 
	{
		RetVal=FALSE;
		syslog(Settings.ErrorLogLevel,"%s In IP Deny List. Denying Login.",Session->ClientIP);
	}
}

if (StrValid(Settings.AllowMACs))
{
	if (FnmatchInList(Settings.AllowMACs, Session->ClientMAC)) RetVal=TRUE;
}

if (StrValid(Settings.DenyMACs))
{
	if (FnmatchInList(Settings.DenyMACs, Session->ClientMAC)) 
	{
		RetVal=FALSE;
		syslog(Settings.ErrorLogLevel,"%s/%s In MAC Deny List. Denying Login.",Session->ClientIP,Session->ClientMAC);
	}
}

return(RetVal);
}


uid_t JailAndSwitchUser(int Flags, char *User, char *JailDir)
{
struct passwd *pwent=NULL;
uid_t UID=0;

return(0);
if (! StrValid(User)) pwent=getpwnam("nobody");
else pwent=getpwnam(User);

chdir(JailDir);

if (Flags & FLAG_CHROOT) chroot(".");

if (pwent) 
{
	UID=pwent->pw_uid;
	if (setgid(pwent->pw_gid) !=0) exit(20);
//	if (setresuid(UID,UID,UID) !=0) exit(20);
}
else exit(20);

return(UID);
}



void HandleClient()
{
char *Tempstr=NULL;
int i;


	Session=(TSession *) calloc(1,sizeof(TSession));
	Session->Shell=CopyStr(Session->Shell,Settings.DefaultShell);
	Session->TermType=CopyStr(Session->TermType,"vt100");
	Session->S=STREAMFromDualFD(0,1);
	STREAMSetItem(Session->S,"Session",Session);
	STREAMSetTimeout(Session->S,0);
	GetSockDetails(0, &Session->ServerIP, &i, &Session->ClientIP, &i);
	GetClientHardwareAddress(Session);
	Session->ClientHost=CopyStr(Session->ClientHost,IPStrToHostName(Session->ClientIP));

	if (StrValid(Session->ClientMAC)) syslog(Settings.InfoLogLevel,"connection from: %s (%s / %s)", Session->ClientHost, Session->ClientIP, Session->ClientMAC);
	else syslog(Settings.InfoLogLevel,"connection from: %s (%s)", Session->ClientHost, Session->ClientIP);

	if (! CheckClientPermissions(Session)) Session->Flags |= FLAG_DENYAUTH;
	if (StrValid(Settings.TLSCertificate) && StrValid(Settings.TLSKey))
	{
		DoSSLServerNegotiation(Session->S, Settings.TLSCertificate, Settings.TLSKey, 0);
	}

	chdir(Settings.ChDir);
	if (StrValid(Settings.ChDir)==0) chdir(Settings.ChDir);
	if (Settings.Flags & FLAG_CHROOT) chroot(".");

	TelnetSendNegotiation(Session->S, TELNET_WONT, TELNET_LINEMODE);
	TelnetSendNegotiation(Session->S, TELNET_WILL, TELNET_NOGOAHEAD);
	//TelnetSendNegotiation(Session->S, TELNET_DONT, TELNET_LINEMODE);
	TelnetSendNegotiation(Session->S, TELNET_WILL, TELNET_ECHO);
	TelnetSendNegotiation(Session->S, TELNET_DO, TELNET_TERMTYPE);
	TelnetSendNegotiation(Session->S, TELNET_DO, TELNET_WINSIZE);

	if (StrValid(Settings.Banner)) 
	{
		Tempstr=SessionSubstituteVars(Tempstr,Settings.Banner,Session);
		STREAMWriteLine(Tempstr,Session->S);
		STREAMWriteLine("\r\n",Session->S);
	}

	if (strcmp(Settings.AuthMethods,"open")==0) Session->Flags |= FLAG_AUTHENTICATED;
	else
	{
		for (i=0; i < Settings.AuthTries; i++)
		{
			if (Login(Session)) break;
			printf("\r\nLogin incorrect\r\n"); fflush(NULL);

			if (! (Settings.Flags & FLAG_DENYAUTH))  syslog(Settings.ErrorLogLevel,"%s@%s login failed: tries used %d/%d",Session->User,Session->ClientIP,i,Settings.AuthTries);
			sleep(Settings.AuthDelay);
		}
	}


	if (Session->Flags & FLAG_AUTHENTICATED)
	{
		syslog(Settings.InfoLogLevel,"%s@%s logged in after %d tries",Session->User,Session->ClientIP,i);
		RunTelnetSession(Session);
	}
	else syslog(Settings.ErrorLogLevel,"login from %s failed after %d tries",Session->ClientIP,i);

	SessionClose(Session);
	STREAMClose(Session->S);

	Destroy(Tempstr);
	free(Session);
	
	_exit(0);
}

void SetupPidFile()
{
char *Tempstr=NULL;


Tempstr=SessionSubstituteVars(Tempstr,Settings.PidFile,NULL);

PidFile=WritePidFile(Tempstr);
Destroy(Tempstr);
}

static void default_signal_handler(int sig) { /* do nothing */  }



void PTelnetDServerMode()
{
int listensock, fd, i;
struct sigaction sigact;
char *Tempstr=NULL, *IPStr=NULL;

listensock=IPServerInit(SOCK_STREAM, Settings.Interface, Settings.Port);
if (listensock==-1)
{
	printf("ERROR: Cannot bind to port %d on interface %s\n",Settings.Port,Settings.Interface);
	exit(3);
}

if (! (Settings.Flags & FLAG_NODEMON)) demonize();

SetupPidFile();

if (Settings.Flags & FLAG_HONEYPOT) JailAndSwitchUser(FLAG_CHROOT, Settings.RealUser, Settings.ChDir);

while (1)
{
/*Set up a signal handler for SIGCHLD so that our 'select' gets interrupted when something exits*/
sigact.sa_handler = default_signal_handler;   
sigemptyset(&sigact.sa_mask);
sigact.sa_flags = 0;
sigaction(SIGCHLD, &sigact, NULL);

if (FDSelect(listensock, SELECT_READ, NULL)) 
{
	fd=IPServerAccept(listensock, &IPStr);
	if (fork()==0) 
	{
		//Sub processes shouldn't keep the pid file open, only the parent server
		//should
		close(PidFile);

		//if we've been passed a socket, then make it into stdin/stdout/stderr
		//but don't do this is fd==0, because then this has already been done by inetd
		close(0);
		close(1);
		close(2);
		dup(fd);
		dup(fd);
		dup(fd);

		//Having dupped it we no longer need to keep this copy open
		close(fd);
		Tempstr=MCopyStr(Tempstr, g_argv[0]," ",IPStr,NULL);
		for (i=0; i <g_argc; i++) memset(g_argv[i],0,StrLen(g_argv[i]));
		strcpy(g_argv[0],Tempstr);

		//In case logging demon was restarted, ensure we have connection before we chroot
		openlog(Settings.LogID,LOG_PID|LOG_NDELAY,LOG_DAEMON);
		HandleClient();

		//Should be redundant, but if something goes wrong in HandleClient, we might want this
		//exit call
		_exit(0);
	}
	close(fd);
}
waitpid(-1,NULL,WNOHANG);
}

}



int main(int argc, char *argv[])
{
g_argc=argc;
g_argv=argv;

SettingsInit();
SettingsParseCommandLine(argc, argv);

//LOG_NDELAY to open connection immediately. That way we inherit the connection
//when we chroot
openlog(Settings.LogID,LOG_PID|LOG_NDELAY,LOG_DAEMON);

//Check if settings are valid. Abort if the user has asked for something stupid and/or dangerous.
if (! SettingsPostProcess()) exit(2);


if (Settings.Flags & FLAG_INETD)
{
	if (Settings.Flags & FLAG_HONEYPOT) JailAndSwitchUser(FLAG_CHROOT, Settings.RealUser, Settings.ChDir);
	HandleClient();
}
else PTelnetDServerMode();

return(0);
}

