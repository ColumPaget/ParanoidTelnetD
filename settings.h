
#ifndef PARANOID_TELNET_CONFIG_H
#define PARANOID_TELNET_CONFIG_H

#include "common.h"

typedef struct
{
unsigned int Flags;
char *AllowUsers;
char *DenyUsers;
char *AllowIPs;
char *DenyIPs;
char *AllowMACs;
char *DenyMACs;
char *LogID;
char *AuthFile;
char *AuthMethods;
char *ChDir;
char *Interface;
char *RealUser;
char *Banner;
char *Environment;
char *DynamicHomeDir;
char *DefaultShell;
char *LoginScript;
char *LogoutScript;
char *PidFile;
char *ProcessConfig;
char *TLSCertificate;
char *TLSKey;
char *SUGroup;
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


void SettingsInit();
int SettingsPostProcess();
void SettingsParseCommandLine(int argc, char *argv[]);

#endif

