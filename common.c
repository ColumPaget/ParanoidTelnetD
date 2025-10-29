#include "common.h"



int SetNoSU()
{
#ifdef USE_NOSU
  #ifdef HAVE_LINUX_PRCTL_H
  #include <sys/prctl.h>
  
  //set, then check that the set worked. This correctly handles situations where we ask to set more than once
  //as the second attempt may 'fail', but we already have the desired result
      prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
      if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1) return(TRUE);
  #else
  RaiseError(ERRFLAG_SYSLOG, "SetNoSU", "ERROR: 'nosu' feature specified, but not supported by platform\n");
  exit(20);
  #endif
#else
  RaiseError(ERRFLAG_SYSLOG, "SetNoSU", "ERROR: 'nosu' feature specified, but not compiled-in to ptelnetd\n");
  exit(20);
#endif

    return(FALSE);
}
