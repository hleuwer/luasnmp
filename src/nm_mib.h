/*
 * nm_mib.h
 */

#ifndef nm_mib_h
#define	nm_mib_h

#include "nm_util.h"
#include "nm_mibdefs.h"

int nm_mib_register(lua_State *L, char *modulename);

#endif
