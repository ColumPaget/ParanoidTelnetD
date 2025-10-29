#include "Authenticate.h"
#include "settings.h"
#include <pwd.h>


#include <stdio.h> /* For NULL */

#ifdef HAVE_LIBCRYPT
#include <crypt.h>
#endif


#ifdef HAVE_LIBPAM
#include <security/pam_appl.h>

pam_handle_t *pamh=NULL;
#endif

#define USER_UNKNOWN -1

char *AuthenticationsTried=NULL;

static int CheckServerAllowDenyLists(const char *UserName)
{
    char *Token=NULL;
    const char *ptr;

    if (StrLen(Settings.DenyUsers))
    {
        ptr=GetToken(Settings.DenyUsers,"\\S",&Token,GETTOKEN_QUOTES);

        while (ptr)
        {
            if (strcmp(Token,UserName)==0)
            {
                syslog(Settings.ErrorLogLevel,"UserName '%s' in 'DenyUsers' list. Login Denied",UserName);
                Destroy(Token);
                return(FALSE);
            }
            ptr=GetToken(ptr,"\\S",&Token,GETTOKEN_QUOTES);
        }

    }

    if (! StrLen(Settings.AllowUsers))
    {
        Destroy(Token);
        return(TRUE);
    }

    ptr=GetToken(Settings.AllowUsers,"\\S",&Token,GETTOKEN_QUOTES);
    while (ptr)
    {
        if (strcmp(Token,UserName)==0)
        {
            syslog(Settings.ErrorLogLevel,"UserName '%s' Found in 'AllowUsers' list.",UserName);
            Destroy(Token);
            return(TRUE);
        }
        ptr=GetToken(ptr,"\\S",&Token,GETTOKEN_QUOTES);
    }

    return(FALSE);
}



//Get details like home dir and shell that are stored in the passwd file
//even if authentication happens against, say, the shadow file
static void PasswordFileGetDetails(TSession *Session)
{
    struct passwd *pass_struct;

    pass_struct=getpwnam(Session->User);

    if (pass_struct != NULL)
    {
        Session->HomeDir=CopyStr(Session->HomeDir, pass_struct->pw_dir);
        Session->Shell=CopyStr(Session->Shell, pass_struct->pw_shell);
        Session->RealUser=CopyStr(Session->RealUser, Session->User);
    }
}


static int AuthPasswordFile(TSession *Session)
{
    struct passwd *pass_struct;

    AuthenticationsTried=CatStr(AuthenticationsTried,"passwd ");
    pass_struct=getpwnam(Session->User);

    if (pass_struct==NULL) return(USER_UNKNOWN);

#ifdef HAVE_LIBCRYPT
    if (StrValid(Session->Password) && StrValid(pass_struct->pw_passwd))
    {
        if (strcmp(pass_struct->pw_passwd, crypt(Session->Password,pass_struct->pw_passwd))==0)
        {
            PasswordFileGetDetails(Session);
            return(TRUE);
        }
    }

#endif


    return(FALSE);
}


static int AuthShadowFile(TSession *Session)
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

        if (sptr && (strcmp(Digest,sptr)==0) )
        {
            result=TRUE;
        }
    }
    else if (StrLen(Session->Password) && StrLen(pass_struct->sp_pwdp))
    {
        // assume old des crypt password
        sptr=crypt(Session->Password,pass_struct->sp_pwdp);
        if (sptr && (strcmp(pass_struct->sp_pwdp, sptr)==0))
        {
            result=TRUE;
        }
    }


#endif

    //if we authenticated sucessfully then setup session using details like
    //homedir and shell from password file
    if (result) PasswordFileGetDetails(Session);

#endif
    Destroy(Salt);
    Destroy(Digest);

    return(result);
}


#ifdef HAVE_LIBPAM

/* PAM works in a bit of a strange way, insisting on having a callback */
/* function that it uses to prompt for the password. We have arranged  */
/* to have the password passed in as the 'appdata' arguement, so this  */
/* function just passes it back!                                       */

static int PAMConvFunc(int NoOfMessages, const struct pam_message **messages,
                       struct pam_response **responses, void *appdata)
{
    int count;
    const struct pam_message *mess;
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



static int PAMStart(TSession *Session, const char *User)
{
    static struct pam_conv  PAMConvStruct = {PAMConvFunc, NULL };
    const char *PAMConfigs[]= {"ptelnetd","telnet","other",NULL};
    int result=PAM_PERM_DENIED, i;

    PAMConvStruct.appdata_ptr=(void *)Session->Password;

    for (i=0; (PAMConfigs[i] != NULL) && (result != PAM_SUCCESS); i++)
    {
        result=pam_start(PAMConfigs[i],User,&PAMConvStruct,&pamh);
    }

    if (result==PAM_SUCCESS)
    {
        pam_set_item(pamh,PAM_RUSER,Session->User);
        if (StrLen(Session->ClientHost) > 0) pam_set_item(pamh,PAM_RHOST,Session->ClientHost);
        else if (StrLen(Session->ClientIP) > 0) pam_set_item(pamh,PAM_RHOST,Session->ClientIP);
        else pam_set_item(pamh,PAM_RHOST,"");
        return(TRUE);
    }

    return(FALSE);
}



static int AuthPAM(TSession *Session)
{
    static struct pam_conv  PAMConvStruct = {PAMConvFunc, NULL };
    int result;

    AuthenticationsTried=CatStr(AuthenticationsTried,"pam ");

    if(! PAMStart(Session, Session->User))
    {
        return(USER_UNKNOWN);
    }

    result=pam_authenticate(pamh,0);

    if (result==PAM_SUCCESS)
    {
        Session->RealUser=CopyStr(Session->RealUser,Session->User);
        return(TRUE);
    }
    else return(FALSE);
}



static int AuthPAMCheckSession(TSession *Session)
{
    if (! pamh)
    {
        if (! PAMStart(Session, Session->RealUser)) return(FALSE);
    }

    if (pam_acct_mgmt(pamh, 0)==PAM_SUCCESS)
    {
        pam_open_session(pamh, 0);
        return(TRUE);
    }
    return(FALSE);
}



static void AuthPAMClose()
{
    if (pamh)
    {
        pam_close_session(pamh, 0);
        pam_end(pamh,PAM_SUCCESS);
    }
}
#endif



char *GetDefaultUser()
{
    char *Possibilities[]= {"nobody","daemon","guest",NULL};
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



static int NativeFileCheckPassword(const char *Name, const char *PassType, const char *Salt, const char *Password, const char *ProvidedPass)
{
    char *Digest=NULL, *Tempstr=NULL, *Token=NULL, *ptr;
    int result=FALSE;

    if (! PassType) return(FALSE);
    if (! Password) return(FALSE);
    if (! ProvidedPass) return(FALSE);

    if (strcmp(PassType,"null")==0) return(TRUE);
    if (strcmp(PassType,"plain")==0)
    {
        if(strcmp(Password,ProvidedPass)==0) return(TRUE);
        return(FALSE);
    }

    if (strncmp(PassType,"cr-",3)==0)
    {
        Tempstr=MCopyStr(Tempstr,Salt,":",Password,NULL);
        HashBytes(&Digest, PassType+3, Tempstr, StrLen(Tempstr), ENCODE_HEX);
        if (strcasecmp(Digest,ProvidedPass)==0) result=TRUE;
    }
    else  if (StrLen(PassType) && StrLen(ProvidedPass))
    {
        if (StrLen(Salt))
        {
            //Salted passwords as of version 1.1.1
            Tempstr=MCopyStr(Tempstr,Name,":",ProvidedPass,":",Salt,NULL);
            HashBytes(&Digest, PassType, Tempstr, StrLen(Tempstr), ENCODE_BASE64);
        }
        //Old-style unsalted passwords
        else HashBytes(&Digest,PassType,ProvidedPass,StrLen(ProvidedPass),ENCODE_HEX);

        if (StrLen(Digest) && (strcmp(Password,Digest)==0)) result=TRUE;
    }

    Destroy(Tempstr);
    Destroy(Digest);
    Destroy(Token);

    return(result);
}




static int AuthNativeFile(TSession *Session, const char *AuthType, const char *AuthFile)
{
    STREAM *S;
    char *Tempstr=NULL, *Name=NULL, *Pass=NULL, *RealUser=NULL, *HomeDir=NULL, *PassType=NULL, *Salt=NULL, *Shell=NULL, *ProcessConfig=NULL;
    const char *ptr;
    int RetVal=USER_UNKNOWN;
    struct passwd *pass_struct;

    AuthenticationsTried=MCatStr(AuthenticationsTried, AuthType, ":", AuthFile, " ", NULL);
    if (StrValid(AuthFile))
    {
        S=STREAMOpen(AuthFile,"r");
        if (! S) return(USER_UNKNOWN);

        Tempstr=STREAMReadLine(Tempstr,S);
        while (Tempstr)
        {
            StripTrailingWhitespace(Tempstr);
            ptr=GetToken(Tempstr,":",&Name,0);
            ptr=GetToken(ptr,":",&PassType,0);

            //plain passwords aren't salted, but can be used with challenge/response, in which case the 'salt' is
            //is the challenge string
            if (strcasecmp(PassType,"plain") ==0)
            {
                Salt=CopyStr(Salt, Session->Challenge);
                if (strncmp(AuthType,"cr-",3)==0) PassType=CopyStr(PassType, AuthType);
            }
            else ptr=GetToken(ptr,"$",&Salt,0);

            ptr=GetToken(ptr,":",&Pass,0);
            ptr=GetToken(ptr,":",&RealUser,0);
            ptr=GetToken(ptr,":",&HomeDir,0);
            ptr=GetToken(ptr,":",&Shell,0);
            ptr=GetToken(ptr,":",&ProcessConfig,0);

            if (strcasecmp(Name,Session->User)==0)
            {
                RetVal=FALSE;

                if (NativeFileCheckPassword(Name,PassType,Salt,Pass,Session->Password))
                {
                    RetVal=TRUE;
                    Session->RealUser=CopyStr(Session->RealUser,RealUser);
                    if (StrValid(HomeDir)) Session->HomeDir=CopyStr(Session->HomeDir,HomeDir);
                    if (StrValid(Shell)) Session->Shell=CopyStr(Session->Shell,Shell);
                    if (StrValid(ProcessConfig)) Session->ProcessConfig=CopyStr(Session->ProcessConfig,ProcessConfig);
                    break;
                }
            }

            Tempstr=STREAMReadLine(Tempstr,S);
        }
        STREAMClose(S);
    }

    Destroy(Tempstr);
    Destroy(Name);
    Destroy(Pass);
    Destroy(Salt);
    Destroy(Shell);
    Destroy(HomeDir);
    Destroy(RealUser);
    Destroy(PassType);
    Destroy(ProcessConfig);

    return(RetVal);
}


static int AuthNativeFiles(TSession *Session, const char *AuthType)
{
    char *Path=NULL;
    const char *ptr;
    int result=FALSE, RetVal=USER_UNKNOWN;

    ptr=GetToken(Settings.AuthFile, ":", &Path, GETTOKEN_QUOTES);
    while (ptr)
    {
        result=AuthNativeFile(Session, AuthType, Path);
        if (result > RetVal) RetVal=result;
        if (result == TRUE) break;
        ptr=GetToken(ptr, ":", &Path, GETTOKEN_QUOTES);
    }

    Destroy(Path);

    return(RetVal);
}


void ListNativeFile(const char *Path)
{
    STREAM *S;
    char *Tempstr=NULL, *Token=NULL, *SendStr=NULL;
    const char *ptr;

    S=STREAMOpen(Path,"r");
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


    Destroy(Tempstr);
    Destroy(SendStr);
    Destroy(Token);
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
        RetStr=FormatStr(RetStr,"%lux-%lux-%lux-%lux-%lux",getpid(),tv.tv_usec,tv.tv_sec,clock(),rand());
        fprintf(stderr,"WARNING: Failed to open /dev/random. Using less secure 'generated' salt for password.\n");
    }

    Destroy(Tempstr);

    return(RetStr);
}


//add or delete users from the native file
static int UpdateNativeFile(const char *Path, const char *Name, const char *PassType, const char *Pass, const char *HomeDir, const char *RealUser, const char *Shell, const char *Args, int Action)
{
    STREAM *S;
    ListNode *Entries;
    char *Tempstr=NULL, *Token=NULL, *Salt=NULL;
    int RetVal=FALSE;
    ListNode *Curr;

    Entries=ListCreate();
    MakeDirPath(Path, 0700);
    S=STREAMOpen(Path,"r");
    if (S)
    {
        Tempstr=STREAMReadLine(Tempstr,S);
        while (Tempstr)
        {
            GetToken(Tempstr,":",&Token,0);
            if (strcmp(Token, Name) != 0) ListAddNamedItem(Entries,Token,CopyStr(NULL,Tempstr));

            Tempstr=STREAMReadLine(Tempstr,S);
        }
        STREAMClose(S);
    }


    if (StrLen(Path))
    {
        S=STREAMOpen(Path,"w");
        if (S)
        {
            //First copy all other entries
            Curr=ListGetNext(Entries);
            while (Curr)
            {
                STREAMWriteLine((char *) Curr->Item, S);
                Curr=ListGetNext(Curr);
            }
            STREAMFlush(S);


            if (Action==NATIVEFILE_USER_DEL)
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
                    Token=MCopyStr(Token,Name,":",Pass,":",Salt,NULL);
                    HashBytes(&Tempstr, PassType, Token, StrLen(Token), ENCODE_BASE64);
                    Token=MCopyStr(Token,Salt,"$",Tempstr,NULL);
                }
                Tempstr=MCopyStr(Tempstr,Name,":",PassType,":",Token,":",RealUser,":",HomeDir,":",Shell,":",Args,"\n",NULL);

                STREAMWriteLine(Tempstr,S);

                //when we create a user, we also create their home directory
                //we do this as the user to get the righ permissions
                if (getuid()==0) SwitchUser(RealUser);
                mkdir(HomeDir,0770);
            }

            STREAMClose(S);
            RetVal=TRUE;
        }
    }

    Destroy(Tempstr);
    Destroy(Token);
    Destroy(Salt);

    ListDestroy(Entries,Destroy);

    return(RetVal);
}



int UpdateNativeFiles(const char *FileList, const char *Name, const char *PassType, const char *Pass, const char *HomeDir, const char *RealUser, const char *Shell, const char *Args, int Action)
{
    char *Path=NULL;
    const char *ptr;
    int RetVal=FALSE;

    ptr=GetToken(FileList, ":", &Path, GETTOKEN_QUOTES);
    while (ptr)
    {
        RetVal=UpdateNativeFile(Path, Name, PassType, Pass, HomeDir, RealUser, Shell, Args, Action);
        if (RetVal==TRUE) break;
        ptr=GetToken(ptr, ":", &Path, GETTOKEN_QUOTES);
    }


    Destroy(Path);
    return(RetVal);
}



int CheckUserExists(const char *UserName)
{
    TSession *Session;
    int result=FALSE;

    if (! UserName) return(FALSE);

    Session=(TSession *) calloc(1,sizeof(TSession));
    Session->User=CopyStr(Session->User,UserName);
    Session->Password=CopyStr(Session->Password,"");

    if (AuthPasswordFile(Session) != USER_UNKNOWN) result=TRUE;
    if (AuthShadowFile(Session) != USER_UNKNOWN) result=TRUE;
    if (AuthNativeFiles(Session, "") != USER_UNKNOWN) result=TRUE;

    Destroy(Session->User);
    Destroy(Session->Password);

    free(Session);

    return(result);
}




int Authenticate(TSession *Session)
{
    int result=0;
    char *Token=NULL;
    const char *ptr;
    struct passwd *pwent;

    AuthenticationsTried=CopyStr(AuthenticationsTried,"");
    if (! CheckUserExists(Session->User))
    {
        return(FALSE);
    }

    AuthenticationsTried=CopyStr(AuthenticationsTried,"");

    if (! CheckServerAllowDenyLists(Session->User)) return(FALSE);

//check for this as it changes behavior of other auth types
    ptr=GetToken(Settings.AuthMethods,",",&Token,0);
    while (ptr)
    {
        if (strcasecmp(Token,"pam-account")==0) Session->Flags |= FLAG_PAM_ACCOUNT;
        ptr=GetToken(ptr,",",&Token,0);
    }

    ptr=GetToken(Settings.AuthMethods,",",&Token,0);
    while (ptr)
    {
        StripLeadingWhitespace(Token);
        StripTrailingWhitespace(Token);
        if (strcasecmp(Token,"native")==0) result=AuthNativeFiles(Session, Token);
        else if (strncasecmp(Token,"cr-",3)==0) result=AuthNativeFiles(Session, Token);
        else if (strcasecmp(Token,"shadow")==0) result=AuthShadowFile(Session);
        else if (strcasecmp(Token,"passwd")==0) result=AuthPasswordFile(Session);
#ifdef HAVE_LIBPAM
        else if (strcasecmp(Token,"pam")==0)
        {
            result=AuthPAM(Session);
            if (result) Session->Flags |= FLAG_PAM_ACCOUNT;
        }
#endif


        if (result==TRUE) break;
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


//check again, because may have changed in above block
    if (result && (Session->Flags & FLAG_PAM_ACCOUNT))
    {
#ifdef HAVE_LIBPAM
        if (! AuthPAMCheckSession(Session)) result=FALSE;
#endif
    }

    if (result==TRUE) Session->Flags |= FLAG_AUTHENTICATED;


    Destroy(Token);
    return(result);
}



void SessionClose(TSession *Session)
{
#ifdef HAVE_LIBPAM
    void AuthPAMClose();
#endif
}


