#ifndef Authenticate_H
#define Authenticate_H

#include "common.h"

#define AUTH_ANY    0
#define AUTH_MD5    1
#define AUTH_SHA1		2
#define AUTH_SHA256		4
#define AUTH_SHA512		8

#define NATIVEFILE_USER_ADD 1
#define NATIVEFILE_USER_LIST 3
#define NATIVEFILE_USER_DEL 4

char *GenerateSalt(char *RetStr, int len);

int CheckUserExists(const char *);
int Authenticate(TSession *);
char *GetUserHomeDir(const char *UserName);

int UpdateNativeFile(const char *Path, const char *Name, const char *PassType, const char *Pass, const char *HomeDir, const char *RealUser, const char *Shell, const char *Args, int Flags);
void ListNativeFile(const char *Path);
void SessionClose(TSession *Session);

#endif
