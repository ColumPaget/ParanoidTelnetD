#include "Authenticate.h"
#include <pwd.h>


#include <stdio.h> /* For NULL */

#ifdef HAVE_LIBCRYPT
#include <crypt.h>
#endif


#ifdef HAVE_LIBPAM
#include <security/pam_appl.h>
#endif

#define USER_UNKNOWN -1

char *AuthenticationsTried=NULL;

int CheckUserExists(char *UserName)
{
TSession *Session;
int result=FALSE;

if (! UserName) return(FALSE);

Session=(TSession *) calloc(1,sizeof(TSession));
Session->User=CopyStr(Session->User,UserName);
Session->Password=CopyStr(Session->Password,"");

if (AuthPasswordFile(Session) != USER_UNKNOWN) result=TRUE;
if (AuthShadowFile(Session) != USER_UNKNOWN) result=TRUE;
if (AuthNativeFile(Session) != USER_UNKNOWN) result=TRUE;

DestroyString(Session->User);
DestroyString(Session->Password);

free(Session);

return(result);
}



int CheckServerAllowDenyLists(char *UserName)
{
char *ptr, *Token=NULL;

if (StrLen(Settings.DenyUsers))
{
ptr=GetToken(Settings.DenyUsers,"\\S",&Token,GETTOKEN_QUOTES);

while (ptr)
{
	if (strcmp(Token,UserName)==0)
	{
		syslog(Settings.ErrorLogLevel,"UserName '%s' in 'DenyUsers' list. Login Denied",UserName);
		DestroyString(Token);
		return(FALSE);
	}
	ptr=GetToken(ptr,"\\S",&Token,GETTOKEN_QUOTES);
}

}

if (! StrLen(Settings.AllowUsers))
{
DestroyString(Token);
return(TRUE);
}

ptr=GetToken(Settings.AllowUsers,"\\S",&Token,GETTOKEN_QUOTES);
while (ptr)
{
	if (strcmp(Token,UserName)==0)
	{
		syslog(Settings.ErrorLogLevel,"UserName '%s' Found in 'AllowUsers' list.",UserName);
		DestroyString(Token);
		return(TRUE);
	}
	ptr=GetToken(ptr,"\\S",&Token,GETTOKEN_QUOTES);
}

return(FALSE);
}




int AuthPasswordFile(TSession *Session)
{
struct passwd *pass_struct;

AuthenticationsTried=CatStr(AuthenticationsTried,"passwd ");
pass_struct=getpwnam(Session->User);

if (pass_struct==NULL) return(USER_UNKNOWN);

#ifdef HAVE_LIBCRYPT
Session->HomeDir=CopyStr(Session->HomeDir,pass_struct->pw_passwd);
Session->Shell=CopyStr(Session->Shell,pass_struct->pw_passwd);

if (StrLen(Session->Password) && StrLen(pass_struct->pw_passwd))
{
if (strcmp(pass_struct->pw_passwd, crypt(Session->Password,pass_struct->pw_passwd))==0)
{
	Session->RealUser=CopyStr(Session->RealUser,Session->User);
	return(TRUE);
}
}

#endif


return(FALSE);
}


int AuthShadowFile(TSession *Session)
{
char *sptr, *eptr, *Salt=NULL, *Digest=NULL;
int result=FALSE;

#ifdef HAVE_SHADOW_H
#include <shadow.h>
struct spwd *pass_struct=NULL;

AuthenticationsTried=CatStr(AuthenticationsTried,"shadow ");
pass_struct=getspnam(Session->User);

if (pass_struct==NULL) return(USER_UNKNOWN);

sptr=pass_struct->sp_pwdp;

#ifdef HAVE_LIBCRYPT

// this is an md5 password
if (
	(StrLen(sptr) > 4) && 
	(strncmp(sptr,"$1$",3)==0)
   )
{
	eptr=strchr(sptr+3,'$');
  Salt=CopyStrLen(Salt,sptr,eptr-sptr);

  Digest=CopyStr(Digest, crypt(Session->Password,Salt));

  if (strcmp(Digest,sptr)==0) 
	{
		result=TRUE;
	}
}
else if (StrLen(Session->Password) && StrLen(pass_struct->sp_pwdp))
{
   // assume old des crypt password

   if (strcmp(pass_struct->sp_pwdp, crypt(Session->Password,pass_struct->sp_pwdp))==0)
   {
      result=TRUE;
   }
}


#endif

if (result) Session->RealUser=CopyStr(Session->RealUser,Session->User);

#endif
DestroyString(Salt);
DestroyString(Digest);

return(result);
}


#ifdef HAVE_LIBPAM

/* PAM works in a bit of a strange way, insisting on having a callback */
/* function that it uses to prompt for the password. We have arranged  */
/* to have the password passed in as the 'appdata' arguement, so this  */
/* function just passes it back!                                       */

int PAMConvFunc(int NoOfMessages, const struct pam_message **messages, 
         struct pam_response **responses, void *appdata)
{
int count;
struct pam_message *mess;
struct pam_response *resp;

*responses=(struct pam_response *) calloc(NoOfMessages,sizeof(struct pam_response));

mess=*messages;
resp=*responses;

for (count=0; count < NoOfMessages; count++)
{
if ((mess->msg_style==PAM_PROMPT_ECHO_OFF) ||
    (mess->msg_style==PAM_PROMPT_ECHO_ON))
    {
      resp->resp=CopyStr(NULL,(char *) appdata); 
      resp->resp_retcode=0;
    }
mess++;
resp++;
}

return(PAM_SUCCESS);
}


int AuthPAM(TSession *Session)
{
static pam_handle_t *pamh;
static struct pam_conv  PAMConvStruct = {PAMConvFunc, NULL };
int result;

AuthenticationsTried=CatStr(AuthenticationsTried,"pam ");
PAMConvStruct.appdata_ptr=(void *)Session->Password;


if(
		(pam_start("telnet",Session->User,&PAMConvStruct,&pamh) !=PAM_SUCCESS) &&
		(pam_start("other",Session->User,&PAMConvStruct,&pamh) !=PAM_SUCCESS)
	)
	{
  	return(USER_UNKNOWN);
	}

/* set the credentials for the remote user and remote host */
pam_set_item(pamh,PAM_RUSER,Session->User);
if (StrLen(Session->ClientHost) > 0) pam_set_item(pamh,PAM_RHOST,Session->ClientHost);
else if (StrLen(Session->ClientIP) > 0) pam_set_item(pamh,PAM_RHOST,Session->ClientIP);
else pam_set_item(pamh,PAM_RHOST,"");


result=pam_authenticate(pamh,0);

pam_end(pamh,PAM_SUCCESS);



if (result==PAM_SUCCESS)
{
	Session->RealUser=CopyStr(Session->RealUser,Session->User);
	return(TRUE);
}
else return(FALSE);
}
#endif



char *GetDefaultUser()
{
char *Possibilities[]={"nobody","daemon","guest",NULL};
TSession *Session;
int i;

Session=(TSession *) calloc(1,sizeof(TSession));

for (i=0; Possibilities[i] !=NULL; i++)
{
	Session->User=CopyStr(Session->User,Possibilities[i]);
	Session->Password=CopyStr(Session->Password,"");
	if (AuthPasswordFile(Session) != USER_UNKNOWN) break;
} 
    
return(Possibilities[i]);  
}



int NativeFileCheckPassword(char *Name, char *PassType,char *Salt,char *Password,char *ProvidedPass)
{
char *Digest=NULL, *Tempstr=NULL;

if (! PassType) return(FALSE);
if (! Password) return(FALSE);
if (! ProvidedPass) return(FALSE);

if (strcmp(PassType,"null")==0) return(TRUE);
if (
      (strcmp(PassType,"plain")==0) &&
      (strcmp(Password,ProvidedPass)==0)
  )
return(TRUE);

if (StrLen(PassType) && StrLen(ProvidedPass))
{
  if (StrLen(Salt))
  {
      //Salted passwords as of version 1.1.1
      Tempstr=MCopyStr(Tempstr,Name,":",ProvidedPass,":",Salt,NULL);
      HashBytes(&Digest, PassType, Tempstr, StrLen(Tempstr), ENCODE_BASE64);
  }
  //Old-style unsalted passwords
  else HashBytes(&Digest,PassType,ProvidedPass,StrLen(ProvidedPass),ENCODE_HEX);

  if (StrLen(Digest) && (strcmp(Password,Digest)==0))
  {
    DestroyString(Digest);
    return(TRUE);
  }
}
DestroyString(Tempstr);
DestroyString(Digest);

return(FALSE);
}




int AuthNativeFile(TSession *Session)
{
STREAM *S;
char *Tempstr=NULL,*ptr;
char *Name=NULL, *Pass=NULL, *RealUser=NULL, *HomeDir=NULL, *PassType=NULL, *Salt=NULL, *Shell=NULL;
int RetVal=USER_UNKNOWN;
struct passwd *pass_struct;

AuthenticationsTried=CatStr(AuthenticationsTried,"native ");

if (StrLen(Settings.AuthFile))
{
S=STREAMOpenFile(Settings.AuthFile,O_RDONLY);
if (! S) 
{
return(USER_UNKNOWN);
}

Tempstr=STREAMReadLine(Tempstr,S);
while (Tempstr)
{
  StripTrailingWhitespace(Tempstr);
	ptr=GetToken(Tempstr,":",&Name,0);
	ptr=GetToken(ptr,":",&PassType,0);
	if (strcasecmp(PassType,"plain") !=0) ptr=GetToken(ptr,"$",&Salt,0);
	ptr=GetToken(ptr,":",&Pass,0);
	ptr=GetToken(ptr,":",&RealUser,0);
	ptr=GetToken(ptr,":",&HomeDir,0);
	ptr=GetToken(ptr,":",&Shell,0);
	
  if (strcasecmp(Name,Session->User)==0)
  {
		RetVal=FALSE;
    if (NativeFileCheckPassword(Name,PassType,Salt,Pass,Session->Password))
    {
			RetVal=TRUE;
			Session->RealUser=CopyStr(Session->RealUser,RealUser);	
			if (StrLen(HomeDir)) Session->HomeDir=CopyStr(Session->HomeDir,HomeDir);	
			if (StrLen(Shell)) Session->Shell=CopyStr(Session->Shell,Shell);	
    }
		break;
  }

  Tempstr=STREAMReadLine(Tempstr,S);
}
STREAMClose(S);
}

DestroyString(Tempstr);
DestroyString(Name);
DestroyString(Pass);
DestroyString(Salt);
DestroyString(Shell);
DestroyString(HomeDir);
DestroyString(RealUser);
DestroyString(PassType);

return(RetVal);
}


void ListNativeFile(char *Path)
{
STREAM *S;
char *Tempstr=NULL, *Token=NULL, *SendStr=NULL, *ptr;

S=STREAMOpenFile(Settings.AuthFile,O_RDONLY);
if (S)
{
  Tempstr=STREAMReadLine(Tempstr,S);
  while (Tempstr)
  {
    StripTrailingWhitespace(Tempstr);
    ptr=GetToken(Tempstr,":",&Token,0);
    SendStr=MCopyStr(SendStr,Token," ",NULL);

    ptr=GetToken(ptr,":",&Token,0); //passtype
    ptr=GetToken(ptr,":",&Token,0); //password
    ptr=GetToken(ptr,":",&Token,0); //realuser
    SendStr=MCatStr(SendStr,"realuser=",Token," ",NULL);
    ptr=GetToken(ptr,":",&Token,0); //homedir
    SendStr=MCatStr(SendStr,"homedir=",Token," ",NULL);
    SendStr=MCatStr(SendStr,ptr,"\n",NULL);

    printf("%s\n",SendStr);
    Tempstr=STREAMReadLine(Tempstr,S);
  }
  STREAMClose(S);
}


DestroyString(Tempstr);
DestroyString(SendStr);
DestroyString(Token);
}


char *GenerateSalt(char *RetStr, int len)
{
int fd, result;
char *Tempstr=NULL;
struct timeval tv;

fd=open("/dev/random",O_RDONLY);
if (fd > -1)
{
  Tempstr=SetStrLen(Tempstr,len);
  result=read(fd,Tempstr,len);
  RetStr=SetStrLen(RetStr,len*4);
  to64frombits(RetStr, Tempstr, result);
  close(fd);
}
else
{
  //if /dev/random is missing, then this should be 'better than nothing'
  gettimeofday(&tv,NULL);
  RetStr=FormatStr(RetStr,"%lux-%lux-%lux-%lux",getpid(),tv.tv_usec,tv.tv_sec,clock());
  fprintf(stderr,"WARNING: Failed to open /dev/random. Using less secure 'generated' salt for password.\n");
}

DestroyString(Tempstr);

return(RetStr);
}



int UpdateNativeFile(char *Path, char *Name, char *PassType, char *Pass, char *HomeDir, char *RealUser, char *Shell, char *Args)
{
STREAM *S;
ListNode *Entries;
char *Tempstr=NULL, *Token=NULL, *Salt=NULL;
ListNode *Curr;
int RetVal=ERR_FILE;

Entries=ListCreate();
S=STREAMOpenFile(Settings.AuthFile,O_RDONLY);
if (S)
{
	Tempstr=STREAMReadLine(Tempstr,S);
	while (Tempstr)
	{
		GetToken(Tempstr,":",&Token,0);

		if (strcmp(Token,Name) !=0) ListAddItem(Entries,CopyStr(NULL,Tempstr));	
	
		Tempstr=STREAMReadLine(Tempstr,S);
	}
	STREAMClose(S);
}


if (StrLen(Settings.AuthFile))
{
	S=STREAMOpenFile(Settings.AuthFile,O_WRONLY| O_CREAT | O_TRUNC);
	if (S)
	{
	//First copy all other entries
	Curr=ListGetNext(Entries);
	while (Curr)
	{
		STREAMWriteLine((char *) Curr->Item,S);
		Curr=ListGetNext(Curr);
	}
	STREAMFlush(S);


	if (strcmp(PassType,"delete")==0)
	{
		//Don't bother to write new entry, effectively deleting user
	}
	else //WriteNew Entry
	{
		//Do this or else HashBytes appends
		Token=CopyStr(Token,"");
		if (strcmp(PassType,"plain") == 0) Token=CopyStr(Token,Pass);
    else
    {
      Salt=GenerateSalt(Salt,16);
      Tempstr=MCopyStr(Tempstr,Name,":",Pass,":",Salt,NULL);
      HashBytes(&Token, PassType, Tempstr, StrLen(Tempstr), ENCODE_BASE64);
    }
    Tempstr=MCopyStr(Tempstr,Name,":",PassType,":",Salt,"$",Token,":",RealUser,":",HomeDir,":",Shell,":",Args,"\n",NULL);

		STREAMWriteLine(Tempstr,S);

		SwitchUser(RealUser);
		mkdir(HomeDir,0770);
	}

	STREAMClose(S);
	RetVal=ERR_OKAY;
	}
}

DestroyString(Tempstr);
DestroyString(Token);
DestroyString(Salt);

ListDestroy(Entries,DestroyString);

return(RetVal);
}
	
int Authenticate(TSession *Session, int AuthType)
{
int result=0;
char *Token=NULL, *ptr;
struct passwd *pwent;

AuthenticationsTried=CopyStr(AuthenticationsTried,"");
if (! CheckUserExists(Session->User))
{
 return(FALSE);
}

AuthenticationsTried=CopyStr(AuthenticationsTried,"");


if (! CheckServerAllowDenyLists(Session->User)) return(FALSE);

ptr=GetToken(Settings.AuthMethods,",",&Token,0);
while (ptr)
{
	StripLeadingWhitespace(Token);
	StripTrailingWhitespace(Token);
	if (strcasecmp(Token,"native")==0) result=AuthNativeFile(Session);
	else if (strcasecmp(Token,"shadow")==0) result=AuthShadowFile(Session);
	else if (strcasecmp(Token,"passwd")==0) result=AuthPasswordFile(Session);
	#ifdef HAVE_LIBPAM
	else if (strcasecmp(Token,"pam")==0) result=AuthPAM(Session);
	#endif

	if (result==TRUE) 
	{
		Session->Flags |= FLAG_AUTHENTICATED;
		break;
	}
	ptr=GetToken(ptr,",",&Token,0);
}

if (result==USER_UNKNOWN) syslog(Settings.ErrorLogLevel,"Authentication failed for UserName '%s'. User Unknown 2. Tried methods: %s ",Session->User,AuthenticationsTried);
else if (result==FALSE) syslog(Settings.ErrorLogLevel,"Authentication failed for UserName '%s'. Bad Password/Credentials. Tried methods: %s ",Session->User,AuthenticationsTried);

//We no longer care if it was 'user unknown' or 'password wrong'
if (result !=TRUE) result=FALSE;



//Don't let them authenticate if HomeDir and user mapping not set

if (result)
{
	if (! StrLen(Session->RealUser)) 
	{
		syslog(Settings.ErrorLogLevel,"No 'RealUser' set for '%s'. Login Denied",Session->User);
		result=FALSE;
	}
	else
	{
		pwent=getpwnam(Session->RealUser);
		if (pwent) 
		{
			Session->RealUserUID=pwent->pw_uid;
			if (! StrLen(Session->HomeDir)) Session->HomeDir=CopyStr(Session->HomeDir,pwent->pw_dir);
		}

		if (! StrLen(Session->HomeDir)) 
		{
			syslog(Settings.ErrorLogLevel,"No 'HomeDir' set for '%s'. Login Denied",Session->User);
			result=FALSE;
		}
	}
}



DestroyString(Token);
return(result);
}




