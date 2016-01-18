#ifndef nm_c64_h
#define nm_c64_h

#ifndef WIN32
#include <sys/types.h>
#endif
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/library/asn1.h>
#include "lua.h"
#include "lauxlib.h"

#define C64NAME "counter64"
#define C64TYPE "snmp counter64"

typedef enum c64_ops {
  C64_ADD,
  C64_SUB,
  C64_EQ,
  C64_LT,
  C64_LE,
  C64_MOD,
  C64_MUL,
  C64_POW,
  C64_NEG,
  C64_TOSTRING,
  C64_TONUMBER,
  C64_TOTABLE,
  C64_TOHEX,
  C64_DIV,
  C64_DIVMOD,
  C64_SQRT,
  C64_COMPARE,
  C64_ISZERO,
} c64_ops_t;

extern const luaL_Reg c64_funcs[];

int c64_new(lua_State *L, struct counter64 val);
struct counter64 c64_get(lua_State *L, int i);
int c64_open(lua_State *L);

#endif
