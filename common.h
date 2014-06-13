#ifndef PARANOID_TELNETD_H
#define PARANOID_TELNETD_H

#include "libUseful-2.0/libUseful.h"

#define VERSION "0.4"

#define ERR_OKAY 0
#define ERR_FILE 1
#define ERR_SIZE 2


//Session and Protocol flags
#define FLAG_AUTHENTICATED 1
#define FLAG_UNMOUNT 16
#define FLAG_DENYAUTH 32

//Settings flags
#define FLAG_NOAUTH 1
#define FLAG_CHROOT 2
#define FLAG_CHHOME 4
#define FLAG_INETD 8
#define FLAG_BLOCK_AUTHFAIL 16
#define FLAG_DYNHOME 32
#define FLAG_DEBUG 64
#define FLAG_LOCALONLY 128
#define FLAG_NODEMON 256
#define FLAG_WINSIZE 512
#define FLAG_FORCE_REALUSER 1024
#define FLAG_FORCE_SHELL 2048
#define FLAG_HONEYPOT 4096
#define FLAG_CHALLENGE 8192
#define FLAG_ERROR 134217728

typedef struct
{
unsigned int Flags;
char *User;
char *Password;
char *RealUser;
char *HomeDir;
int RealUserUID;
int GroupID;
char *ClientHost;
char *ClientIP;
char *ClientMAC;
char *ServerIP;
char *Shell;
time_t LastActivity;
char *Challenge;
STREAM *S;
} TSession;

typedef struct
{
unsigned int Flags;
char *AllowUsers;
char *DenyUsers;
char *AllowIPs;
char *DenyIPs;
char *AllowMACs;
char *DenyMACs;
char *LogPath;
char *AuthFile;
char *AuthMethods;
char *ChDir;
char *Interface;
char *RealUser;
char *BindMounts;
char *Banner;
char *Environment;
char *DynamicHomeDir;
char *DefaultShell;
char *TermType;
char *LoginScript;
char *LogoutScript;
char *PidFile;
int WinWidth, WinLength;
ListNode *BlockHosts;
int Port;
int AuthTries;
int AuthDelay;
int ErrorLogLevel;
int InfoLogLevel;
int IdleTimeout;
int ChallengeResponse;
} TSettings;



extern TSettings Settings;

#endif
