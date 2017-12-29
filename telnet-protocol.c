#include "telnet-protocol.h"

#define TELNET_BACKSPACE 127

//As there is a process per connection,
//it's okay to use globals
int TelnetNegotiatedCount=0;
int *TelnetNegotiatedOptions=NULL;

int TelnetOptionAlreadyNegotiated(int DoWill, int Option)
{
int i;

if (DoWill==TELNET_STARTSUB) return(FALSE);

for (i=0; i < TelnetNegotiatedCount; i++)
{
	if (TelnetNegotiatedOptions[i]==Option) return(TRUE);
}

TelnetNegotiatedOptions=(int *) realloc(TelnetNegotiatedOptions, (TelnetNegotiatedCount+1) * sizeof(int));
TelnetNegotiatedOptions[TelnetNegotiatedCount]=Option;
TelnetNegotiatedCount++;

return(FALSE);
}

void TelnetSendNegotiation(STREAM *S, int DoWill, int Type)
{
	STREAMWriteChar(S,TELNET_IAC);
	STREAMWriteChar(S,DoWill);
	STREAMWriteChar(S,Type);

	STREAMFlush(S);
}

void TelnetSendSubNegotiationRequest(STREAM *S, char Type)
{
	STREAMWriteChar(S, TELNET_IAC);
	STREAMWriteChar(S, TELNET_STARTSUB);
	STREAMWriteChar(S, Type);
	STREAMWriteChar(S, TELNET_SUB_SEND);
	STREAMWriteChar(S, TELNET_IAC);
	STREAMWriteChar(S, TELNET_ENDSUB);
}


void TelnetHandleNegotiation(STREAM *S)
{
int DoWill, Type;
uint16_t Word;
unsigned char *ptr;
TSession *Session;

	//Read past IAC
	Session=(TSession *) STREAMGetItem(S,"Session");
	DoWill=STREAMReadChar(S);
	Type=STREAMReadChar(S);

	if (Settings.Flags & FLAG_DEBUG)
	{
		if (DoWill==TELNET_WILL) syslog(LOG_DEBUG,"TELNET OPTION NEGOTIATION: WILL %d",Type);
		else if (DoWill==TELNET_DO) syslog(LOG_DEBUG,"TELNET OPTION NEGOTIATION: DO %d",Type);
		else if (DoWill==TELNET_STARTSUB) syslog(LOG_DEBUG,"TELNET OPTION SUBNEGOTIATION: %d",Type);
	}

	if (TelnetOptionAlreadyNegotiated(DoWill, Type))
	{
		/*Do Nothing*/
	}
	else if (DoWill==TELNET_WILL) 
	{
		switch (Type)
		{
		case TELNET_TERMTYPE:
			TelnetSendSubNegotiationRequest(S, Type);
		break;

		case TELNET_WINSIZE:
			TelnetSendNegotiation(S, TELNET_DO, Type);
		break;

		default:
			TelnetSendNegotiation(S, TELNET_DONT, Type);
		break;
		}
	}
	else if (DoWill==TELNET_DO) 
	{
		if (Type==TELNET_ECHO) TelnetSendNegotiation(S, TELNET_WILL, Type);
		else if (Type==TELNET_NOGOAHEAD) TelnetSendNegotiation(S, TELNET_WILL, Type);
		else TelnetSendNegotiation(S, TELNET_WONT, Type);
	}
	else if (DoWill==TELNET_STARTSUB)
	{
		switch(Type)
		{
			case TELNET_TERMTYPE:
				//send or is
				DoWill=STREAMReadChar(S);
				Session->TermType=STREAMReadToTerminator(Session->TermType,S,TELNET_IAC);
				//Strip IAC
				ptr=Session->TermType + StrLen(Session->TermType) -1;
				if (*ptr==TELNET_IAC) *ptr='\0';
				StripTrailingWhitespace(Session->TermType);
				strlwr(Session->TermType);
				STREAMReadChar(S); 
				if (Settings.Flags & FLAG_DEBUG) syslog(LOG_DEBUG,"RECEIVED TERMINALTYPE: %s",Session->TermType);
			break;

			case TELNET_WINSIZE:
				STREAMReadBytes(S,(char *) &Word,2);
				Session->TermWidth=ntohs(Word);
				STREAMReadBytes(S,(char *) &Word,2);
				Session->TermHeight=ntohs(Word);
				STREAMReadChar(S);
				STREAMReadChar(S);
				if (Settings.Flags & FLAG_DEBUG) syslog(LOG_DEBUG,"RECEIVED WINDOW SIZE: %dx%d", Session->TermWidth, Session->TermHeight);
				Session->Flags |= FLAG_WINSIZE;
			break;	
		}
	}
}


int TelnetHandleChar(STREAM *S, char *Data, int len, char inchar, char *EchoStr, int Flags)
{
struct timeval tv;

	Data[len]=inchar;

	if (Flags & TNRB_DISCARD_NEXT_CHAR)
	{
		tv.tv_sec=0;
		tv.tv_usec=100000;
		if (STREAMCheckForBytes(S) || FDSelect(S->in_fd,0,&tv)) STREAMReadChar(S);
	}
	
	if (Flags & TNRB_ECHO) 
	{
		if (EchoStr) STREAMWriteBytes(S,EchoStr,strlen(EchoStr));
		else STREAMWriteBytes(S,&inchar,1);
		STREAMFlush(S);
	}
	len++;
return(len);
}


int TelnetReadBytes(STREAM *S, char *Data, int max, int Flags)
{
int inchar;
int len=0;
int result=0;
char tmpChr;

while (1)
{
if ((Flags & TNRB_NONBLOCK) && (STREAMCheckForBytes(S)==0)) break;
if (len >= max) break;

inchar=STREAMReadChar(S);

switch (inchar)
{
case 0:
break;

case EOF: 
	if (len > 0) return(len);
	return(-1);
break;

case TELNET_IAC: 
	if (len > 0) return(len);
	TelnetHandleNegotiation(S);
break;

case '\n':
	return(TelnetHandleChar(S, Data, len, inchar & 0xFF, NULL, 0));
break;

case '\r':
	if (Flags & TNRB_NOPTY) return(TelnetHandleChar(S, Data, len, inchar & 0xFF, "\r\n", Flags | TNRB_DISCARD_NEXT_CHAR));
	else len=TelnetHandleChar(S, Data, len, inchar & 0xFF, NULL, Flags);
break;

case '\b':
case TELNET_BACKSPACE:
	if (Flags & TNRB_NOPTY) 
	{
			if (len > 0)
			{
				len--;
				tmpChr=inchar & 0xFF;
				STREAMWriteBytes(S,&tmpChr,1);
				STREAMFlush(S);
			}
	}
	else len=TelnetHandleChar(S, Data, len, inchar & 0xFF, NULL, Flags);
break;

default:
	len=TelnetHandleChar(S, Data, len, inchar & 0xFF, NULL, Flags);
break;
}

}

return(len);
}

