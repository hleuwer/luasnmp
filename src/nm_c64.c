#include <stdio.h>
#include <math.h>

#include "lua.h"
#include "lauxlib.h"
#include "nm_c64.h"

#define MASK32 0x00000000ffffffffULL

static unsigned long long _pow(double base, double exp)
{
  unsigned long long _base = (unsigned long long) base;
  unsigned long long _exp = (unsigned long long) exp;
  unsigned long long n = 1;
  unsigned long long i;
  for (i = 0; i < _exp; i++)
    n *= _base;
  
  return n;
}
/*
 * Push a 64 bit value as new userdata onto the stack.
 */
int c64_new(lua_State *L, struct counter64 val)
{
   struct counter64 *nval = lua_newuserdata(L, sizeof(struct counter64)); /* ud */
   nval->high = val.high;
   nval->low = val.low;
   luaL_getmetatable(L, C64TYPE);  /* mt, ud */
   lua_setmetatable(L, -2);        /* ud */
   return 1;
}

/*
 * Pop info from stack at index i and return it as 64 bit value.
 * info: userdata, number, table with low and high field.
 */
struct counter64 c64_get(lua_State *L, int i)
{
  struct counter64 val = {0, 0};
   int ul_bits = sizeof(u_long) * 8;

   if (lua_isnumber(L, i)){
     /* Lua number given */
     double dval = lua_tonumber(L, i);
     val.high = (u_long) floor(ldexp(dval, -ul_bits));
     val.low = (u_long) (dval - ldexp(val.high, ul_bits));

   } else if (lua_istable(L, i)){
     /* table {high=<val>, low=<val>} given */
     lua_pushstring(L, "high"); /* key, t */
     lua_gettable(L, -2);       /* val, t */
     val.high = (u_long) lua_tonumber(L, -1);
     lua_remove(L, -1);
     lua_pushstring(L, "low");
     lua_gettable(L, -2);
     val.low = (u_long) lua_tonumber(L, -1);

   } else if (lua_isuserdata(L, i)){
     /* counter64 userdata given */
     struct counter64 *pval;
     pval = luaL_checkudata(L, i, C64TYPE);
     val.high = pval->high;
     val.low = pval->low;
   } 
   c64_new(L, val);     /* c64, param -- i points to param */
   if (i < 0)
     lua_replace(L, i - 1);
   else
     lua_replace(L, i);
   return val;
}

/*
 * Create a 64 bit number as user type
 */
int c64_number(lua_State *L)
{
  c64_get(L, 1);
  lua_settop(L, 1);
  return 1;
}

/*
 * Convert counter64 ==> unsigned long long
 */
static unsigned long long c2u(struct counter64 val)
{
  return (((unsigned long long) val.high) << 32) + val.low;
}

/*
 * Convert unsigned long long ==> counter64
 */
static struct counter64 u2c(unsigned long long val)
{
  struct counter64 retval;
  retval.high = (val >> 32) & MASK32;
  retval.low = (val & MASK32);
  return retval;
}

/*
 * Operations with 1 operand
 */
static int c64_op1(lua_State *L, c64_ops_t op)
{
  unsigned long long a = c2u(c64_get(L, 1));
  struct counter64 c;

  switch (op){
  case C64_TOSTRING:
    {
      char sbuf[64];
      sprintf(sbuf, "%llu", a);
      lua_pushstring(L, sbuf);
    }
    break;
  case C64_TOHEX:
    {
      char sbuf[64];
      sprintf(sbuf, "0x%llx", a);
      lua_pushstring(L, sbuf);
    }
    break;
  case C64_TONUMBER:
    lua_pushnumber(L, a);
    break;
  case C64_TOTABLE:
    c = u2c(a);
    lua_newtable(L);  
    lua_pushstring(L, "high");
    lua_pushnumber(L, c.high);
    lua_settable(L, -3);
    lua_pushstring(L, "low");
    lua_pushnumber(L, c.low);
    lua_settable(L, -3);
    break;
  case C64_NEG:
    c = u2c(-a);
    c64_new(L, c);
    break;
  case C64_SQRT:
    c = u2c(sqrt(a));
    c64_new(L, c);
    break;
  case C64_ISZERO:
    lua_pushboolean(L, (a == 0));
    break;
  default:
    luaL_error(L, "unexpected operand for counter64 type.");
    break;
  }
  return 1;
}

/*
 * Operations with 2 operands
 */
static int c64_op2(lua_State *L, c64_ops_t op)
{
  unsigned long long a = c2u(c64_get(L, 1));
  unsigned long long b = c2u(c64_get(L, 2));
  struct counter64 c;
  int nret = 1;

  switch (op){
  case C64_ADD:
    c = u2c(a + b);
    c64_new(L, c);
    break;
  case C64_SUB:
    c = u2c(a - b);
    c64_new(L, c);
    break;
  case C64_EQ:
    lua_pushboolean(L, (a == b));
    break;
  case C64_LT:
    lua_pushboolean(L, (a < b));
    break;
  case C64_LE:
    if ((a==b) || (a < b))
      lua_pushboolean(L, 1);
    else
      lua_pushboolean(L, 0);
    break;
  case C64_MOD:
    c = u2c(a % b);
    c64_new(L, c);
    break;
  case C64_MUL:
    c = u2c(a * b);
    c64_new(L, c);
    break;
  case C64_POW:
    c = u2c(_pow(a, b));
    c64_new(L, c);
    break;
  case C64_DIV:
    c = u2c(a / b);
    c64_new(L, c);
    break;
  case C64_DIVMOD:
    {
      struct counter64 d;
      c = u2c(a / b);
      d = u2c(a % b);
      c64_new(L, c);
      c64_new(L, d);
      nret += 1;
    }
    break;
  case C64_COMPARE:
    if (a > b)
      lua_pushnumber(L, 1);
    else if (a < b)
      lua_pushnumber(L, -1);
    else 
      lua_pushnumber(L, 0);
    break;
  default:
    luaL_error(L, "unexpected operand for counter64 type.");
    break;
  }
  return nret;
}
/*
 * Methods
 */
int c64_add(lua_State *L) {return c64_op2(L, C64_ADD);}
int c64_sub(lua_State *L) {return c64_op2(L, C64_SUB);}
int c64_eq(lua_State *L) {return c64_op2(L, C64_EQ);}
int c64_lt(lua_State *L) {return c64_op2(L, C64_LT);}
int c64_le(lua_State *L) {return c64_op2(L, C64_LE);}
int c64_mod(lua_State *L) {return c64_op2(L, C64_MOD);}
int c64_mul(lua_State *L) {return c64_op2(L, C64_MUL);}
int c64_pow(lua_State *L) {return c64_op2(L, C64_POW);}
int c64_neg(lua_State *L) {return c64_op1(L, C64_NEG);}
int c64_tostring(lua_State *L) {return c64_op1(L, C64_TOSTRING);}
int c64_tohex(lua_State *L) {return c64_op1(L, C64_TOHEX);}
int c64_tonumber(lua_State *L) {return c64_op1(L, C64_TONUMBER);}
int c64_totable(lua_State *L) {return c64_op1(L, C64_TOTABLE);}
int c64_div(lua_State *L) {return c64_op2(L, C64_DIV);}
int c64_divmod(lua_State *L) {return c64_op2(L, C64_DIVMOD);}
int c64_compare(lua_State *L) {return c64_op2(L, C64_COMPARE);}
int c64_sqrt(lua_State *L) {return c64_op1(L, C64_SQRT);}
int c64_iszero(lua_State *L) {return c64_op1(L, C64_ISZERO);}


const luaL_Reg c64_funcs[] = {
  {"__add", c64_add},
  {"__sub", c64_sub},
  {"__eq", c64_eq},
  {"__lt", c64_lt},
  {"__le", c64_le},
  {"__mod", c64_mod},
  {"__mul", c64_mul},
  {"__pow", c64_pow},
  {"__unm", c64_neg},
  {"__tostring", c64_tostring},
  {"__div", c64_div},
  {"number", c64_number},
  {"add", c64_add},
  {"sub", c64_sub},
  {"compare", c64_compare},
  {"mod", c64_mod},
  {"mul", c64_mul},
  {"neg", c64_neg},
  {"tostring", c64_tostring},
  {"div", c64_div},
  {"divmod", c64_divmod},
  {"sqrt", c64_sqrt},
  {"pow", c64_pow},
  {"iszero", c64_iszero},
  {"totable", c64_totable},
  {"tohex", c64_tohex},
  {"tonumber", c64_tonumber},
  {NULL, NULL}
};

int c64_open(lua_State *L)
{
  /* new metatable for 64 bit counter userdata in registry */ 
  luaL_newmetatable(L, C64TYPE);       /* mt, mod */
#if LUA_VERSION_NUM > 501
  luaL_setfuncs(L, c64_funcs, 0);
#else
  luaL_register(L, NULL, c64_funcs);   /* mt, mod */
#endif
  lua_pushliteral(L, C64NAME);         /* key, mt, mod */
  lua_pushvalue(L, -2);                /* mt, key, mt, mod */
  lua_settable(L, -4);                 /* mt, mod */
  lua_pushliteral(L, "__index");       /* key, mt, mod */
  lua_pushvalue(L, -2);                /* mt, key, mt, mod */
  lua_settable(L, -3);                 /* mt, mod */
  lua_remove(L, -1);                   /* mt */
  return 0;
}
