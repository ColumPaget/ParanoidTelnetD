#ifndef Authenticate_H
#define Authenticate_H

#include "common.h"

#define AUTH_ANY    0
#define AUTH_MD5    1
#define AUTH_SHA1		2
#define AUTH_SHA256		4
#define AUTH_SHA512		8

char *GenerateSalt(char *RetStr, int len);

int CheckUserExists(char *);
int Authenticate(TSession *);
char *GetUserHomeDir(char *UserName);

int UpdateNativeFile(char *Path, char *Name, char *PassType, char *Pass, char *HomeDir, char *RealUser, char *Shell, char *Args);
void ListNativeFile(char *Path);
void SessionClose(TSession *Session);

#endif
