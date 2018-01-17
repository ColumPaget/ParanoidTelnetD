
#ifndef PARANOID_TELNET_CONFIG_H
#define PARANOID_TELNET_CONFIG_H

#include "common.h"

void SettingsInit();
int SettingsPostProcess();
void SettingsParseUserCommandLine(int argc, char *argv[]);
void SettingsParseCommandLine(int argc, char *argv[]);

#endif

