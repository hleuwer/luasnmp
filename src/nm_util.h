/*
 * nm_util.h
 */

#ifndef nm_util_h
#define	nm_util_h

#include "snmp.h"

#include "nm_varbind.h"
#include "lua.h"

#define lua_Object int

#ifndef NULL
#define NULL 0
#endif
 
#ifndef TRUE
#define TRUE    1
#endif
#ifndef FALSE
#define FALSE   0
#endif
 
#define NMAX_SUBID	64

#define FULL_NAME	1
#define LAST_NAME	0

/*
 * Traducao dos codigos de tipo CMU->primitivas SNMP
 */
 
typedef struct Tsnmptype {
        u_char cmu_type;
        int prim_type;
        int last;
} Tsnmptype;

 
/*
 * Traducao dos codigos de erro CMU->primitivas SNMP
 */
 
typedef struct Tsnmperr {
        int cmu_err;
        int prim_err;
        int last;
} Tsnmperr;
 
 
/*
 * Prototipos das funcoes definidas por nm_util
 */
extern int vbindmetatable;
int f_isoid(char *str);
void f_oid2str(oid *objid, int objidlen, char *oidbuf);
int f_str2oid(oid *objid, char *oidbuf, int max_subid);
int f_mibnode2oid(struct snmp_mib_tree *tp, oid *objid);
struct snmp_mib_tree *f_getmibnode(char *buf, oid *objid, int *objidlen);
struct snmp_mib_tree *f_var2mibnode(lua_State *L, oid *objid, int *objidlen);
int f_prim_err(int cod_cmu);
int f_create_vb(lua_State *L, struct variable_list *var);
struct variable_list *f_create_vl(lua_State *L, int prim_type);
struct variable_list *f_create_vlist_from_objid(lua_State *L, oid *objid, int *objidlen, char *errs);
struct variable_list *f_create_vlist(lua_State *L, char *errs);
int f_create_vbind(lua_State *L, int islist,struct variable_list *varlist);
u_long f_uptime(void);
struct variable_list *f_create_infovl(char *trapOID);
void f_trapconv(struct snmp_pdu *pdu);
void f_setup_oid(oid * it, size_t * len, u_char * id, size_t idlen, const char *user);
int f_create_counter64(lua_State *L, struct counter64 val);
#define f_create_integer64(L, val) f_create_counter(L, val)
#endif
