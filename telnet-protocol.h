
#ifndef PARANOID_TELNET_PROTOCOL_H
#define PARANOID_TELNET_PROTOCOL_H

#include "common.h"

#define TELNET_NEGOTITATE -2

#define TELNET_ECHO 1
#define TELNET_NOGOAHEAD 3
#define TELNET_TERMTYPE 24
#define TELNET_WINSIZE  31
#define TELNET_LINEMODE 34


#define TELNET_ENDSUB 240
#define TELNET_NOOP 241
#define TELNET_DATA 242
#define TELNET_BREAK 243
#define TELNET_INTERRUPT 244
#define TELNET_ABORT 245
#define TELNET_AYT 246
#define TELNET_ERASE 247
#define TELNET_ERASELINE 248
#define TELNET_GOAHEAD 249
#define TELNET_STARTSUB 250
#define TELNET_WILL 251
#define TELNET_WONT 252
#define TELNET_DO 253
#define TELNET_DONT 254
#define TELNET_IAC 255

#define TELNET_SUB_IS 0
#define TELNET_SUB_SEND 1

void TelnetSendNegotiation(STREAM *S, int DoWill, int Type);
void 	TelnetHandleNegotiation(STREAM *S);
int TelnetReadBytes(STREAM *S, char *Data, int max, int NonBlock);

#endif
