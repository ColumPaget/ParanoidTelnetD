#ifndef PARANOID_TELNETD_H
#define PARANOID_TELNETD_H

#ifdef USE_LIBUSEFUL_BUNDLED
#include "libUseful-bundled/libUseful.h"
#else
#include "libUseful-5/libUseful.h"
#endif

#define VERSION "4.3"

#define ERR_OKAY 0
#define ERR_FILE 1
#define ERR_SIZE 2


//Session and Protocol flags
#define FLAG_AUTHENTICATED 1
#define FLAG_UNMOUNT 16
#define FLAG_DENYAUTH 32
#define FLAG_PAM_ACCOUNT 64

//Settings flags
#define FLAG_NOAUTH          1
#define FLAG_CHROOT          2
#define FLAG_CHHOME          4
#define FLAG_INETD           8
#define FLAG_BLOCK_AUTHFAIL 16
#define FLAG_DYNHOME        32
#define FLAG_DEBUG          64
#define FLAG_LOCALONLY     128
#define FLAG_NODEMON       256
#define FLAG_WINSIZE       512
#define FLAG_FORCE_REALUSER 1024
#define FLAG_FORCE_SHELL  2048
#define FLAG_HONEYPOT     4096
#define FLAG_LOGCREDS     8192
#define FLAG_CHALLENGE   16384
#define FLAG_NONROOT     32768
#define FLAG_NOSU        65536
#define FLAG_ERROR   134217728


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
char *ProcessConfig;
char *TermType;
int TermWidth;
int TermHeight;
STREAM *S;
} TSession;


int SetNoSU();

#endif
