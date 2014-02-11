#ifndef Authenticate_H
#define Authenticate_H

#include "common.h"

#define AUTH_ANY    0
#define AUTH_PASSWD 1
#define AUTH_SHADOW 2
#define AUTH_NATIVE 3
#define AUTH_MD5    4
#define AUTH_PAM    5

int CheckUserExists(char *);
int Authenticate(TSession *, int);
int AuthPasswdFile(TSession *);
int AuthShadowFile(TSession *);
int AuthNativeFile(TSession *);
int AuthMD5(TSession *);
int AuthPAM(TSession *);
//void EncodeMD5(char *, char *,int);
char *GetUserHomeDir(char *UserName);

int UpdateNativeFile(char *Path, char *Name, char *PassType, char *Pass, char *HomeDir, char *RealUser, char *Shell, char *Args);
void ListNativeFile(char *Path);


#endif
