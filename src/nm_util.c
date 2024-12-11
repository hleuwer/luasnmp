/*-----------------------------------------------------------------------------
 * nm_util.c
 *
 * Helper functions
 * Funcoes auxiliares
 *-----------------------------------------------------------------------------*/

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/mib_api.h>
#if 0 /* CMU compatablity was removed in net-snmp */
#include <net-snmp/library/cmu_compat.h>
#endif
#include <net-snmp/library/asn1.h>
#include <net-snmp/library/snmp_impl.h>

#ifndef WIN32
#include <sys/param.h>
#endif

#include <string.h>
#include <stdio.h>

#include <stdlib.h>

#include <ctype.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <math.h>

#include "nm_snmpdefs.h"
#include "nm_util.h"
#include "nm_varbind.h"
#include "nm_c64.h"

/*-----------------------------------------------------------------------------
 * Local Variables
 * Variaveis Locais
 *----------------------------------------------------------------------------*/

#define UPTIME_LEN 9
#define TRAPOID_LEN 11
#define TRAPENT_LEN 11
#define STDTRAP_LEN 10

static oid sysUpTimeOid[]   = {1,3,6,1,2,1,1,3,0};
static oid snmpTrapOid[]    = {1,3,6,1,6,3,1,1,4,1,0};
static oid snmpTrapEntOid[] = {1,3,6,1,6,3,1,1,4,3,0};
static oid snmpStdTrapOid[] = {1,3,6,1,6,3,1,1,5,0};

int vbindmetatable = -1;

/*-----------------------------------------------------------------------------
 * Compare MIB labels, ignoring case
 *----------------------------------------------------------------------------*/
static int mib_label_cmp(char *l1, char *l2)
{
    char c1, c2;
    for ( ; *l1 && *l2 ; l1++, l2++) {
	if (isupper(*l1))
	    c1 = tolower(*l1);
	else
	    c1 = *l1;
	if (isupper(*l2))
	    c2 = tolower(*l2);
	else
	    c2 = *l2;
	if (c1 != c2)
	    return (0);
    }
    if (*l1 || *l2) return 0;
    return 1;
}

/*-----------------------------------------------------------------------------
 * f_isoid
 *
 * Check if string represents an OID
 * Testa se uma string e' uma representacao de um OID
 *----------------------------------------------------------------------------*/
int f_isoid(char *str) {
  register char *pstr = str;

  if ((!pstr) || (*pstr == '\0'))
    return 0;
  while (1) {
    while (isdigit(*pstr))
      pstr++;
    if (*pstr) {
      if ( *pstr == '.' )
        pstr ++;
      else
        return 0;
    } else
      return 1;
  }
}


/*-----------------------------------------------------------------------------
 * f_oid2str
 *
 * Convert OID into string with "dotted notation"
 * Traduz um oid CMU para uma string em "dotted notation"
 *----------------------------------------------------------------------------*/
void f_oid2str(oid *objid, int objidlen, char *oidbuf) {
  int i;
  oid *nxtsub = objid;
  char strsub[64];

  *oidbuf=0;
  for (i=objidlen ; i > 0 ; i--, nxtsub++) {
    sprintf(strsub,"%d.",(int) *nxtsub);
    strcat(oidbuf,strsub);
  }
  oidbuf[strlen(oidbuf)-1] = 0;
}

/*-----------------------------------------------------------------------------
 * f_str2oid
 *
 * Convert string with "dotted notation" into an OID
 * Traduz uma string em "dotted notation" para um oid CMU
 *----------------------------------------------------------------------------*/
int f_str2oid(oid *objid, char *oidbuf, int max_subid) {
  register char *po = oidbuf;
  register char *ps;
  oid *nxtsub = objid;
  char strsub[64];
  int objidlen;


  for (objidlen = 0; (*po) && (objidlen < max_subid) ; objidlen++ , nxtsub++) {
    ps = strsub;
    while ((*po) && (*po != '.'))
      *ps++ = *po++;
    *ps = 0;
    *nxtsub = atoi(strsub);
    if (*po == '.')
      po++;
  }

  return (objidlen);
}

/*-----------------------------------------------------------------------------
 *  f_mibnode2oid
 *
 * Dado um no na arvore MIB global, recupera o OID completo
 *----------------------------------------------------------------------------*/

int f_mibnode2oid(struct snmp_mib_tree *tp, oid *objid) {
  oid newname[NMAX_SUBID], *op;
  int objidlen= 0;

  for (op = &newname[NMAX_SUBID-1]; op >= newname; op--) {
    *op = tp->subid;
    objidlen++;
    if (!(tp = tp->parent))
      break;
  }
  if (tp)
    return 0;
  memcpy(objid,op,(objidlen *sizeof(oid)));
  return objidlen;
}

/*-----------------------------------------------------------------------------
 *   f_getmibnode
 *
 * Dada uma string obtem o oid correspondente e o ponteiro na arvore MIB 
 *----------------------------------------------------------------------------*/

struct snmp_mib_tree *f_getmibnode(char *buf, oid *objid, int *objidlen) {
  register char *pbuf;
  register char *paux;
  char *cbuf;
  char *vptr, *mptr = NULL;
  char aux[128];
  struct snmp_mib_tree *subtree = Mib;
  struct snmp_mib_tree *node = NULL;
  int oidlen = 0;
  oid *nxtoid = objid;
  u_long subid =0;
  
  if (!buf) return NULL;

  cbuf = strdup(buf);
  if (!cbuf){
    return NULL;
  } else
    pbuf = cbuf;

  if ((vptr = strstr((const char *)pbuf, "::")) != NULL){
    mptr = pbuf;
    *vptr = '\0';
    pbuf = vptr + 2;
  } else if ((vptr = strchr((const char *) pbuf, ':')) != 0){
    mptr = pbuf;
    *vptr = '\0';
    pbuf = vptr + 1;
  }

  /* Protecoes iniciais */
  while (*pbuf == '.')
    pbuf++;

  /* Se nao comeca com digito, procuro o ponto inicial na arvore */
  if (!isdigit(*pbuf)) {
    /* Obtem o primeiro nome */
    paux = aux;
    while ((*pbuf) && (*pbuf != '.'))
      *paux++ = *pbuf++;
    *paux = '\0';
    if (*pbuf == '.')
      pbuf++;
    if (mptr == NULL){
      if (!(subtree = find_node(aux,Mib))){
	free(cbuf);
	return NULL;
      }
    } else {
      if (!(subtree = find_node2(aux, mptr))){
	free(cbuf);
	return NULL;
      }
    }
    /* Obtem o OID ate' aqui */
    if (objid) {
      if ((oidlen = f_mibnode2oid(subtree,nxtoid)) == 0){
	free(cbuf);
        return NULL;
      }
      nxtoid += oidlen;
    }
    node = subtree;
    subtree = subtree->child_list;
  }

  /* Traduz os proximos nomes/subids */
  while (*pbuf) {
    /* Ainda tem espaco para subids ? */
    if ((objid) && (oidlen == NMAX_SUBID)){
      free(cbuf);
      return NULL;
    }
    /* Proximo componente e' um nome ? */
    if (!isdigit(*pbuf)) {
      paux = aux;
      while ((*pbuf) && (*pbuf != '.'))
        *paux++ = *pbuf++;
      if (*pbuf == '.')
        pbuf++;
      *paux = '\0';
      for ( ; subtree ; subtree = subtree->next_peer )
        if (mib_label_cmp(aux,subtree->label)) {
          subid = subtree->subid;
          break;
        };
      if (!subtree){
	free(cbuf);
        return NULL;
      }
    }
    /* Proximo componente e' um subid */
    else {
      subid = 0;
      while (isdigit(*pbuf)) {
        subid *= 10;
        subid += *pbuf++ - '0';
      }
      if (*pbuf) {
        if (*pbuf == '.')
          pbuf++;
        else {
	  free(cbuf);
          return NULL;
	}
      }
      for ( ; subtree ; subtree = subtree->next_peer )
        if (subtree->subid == subid)
          break;

      if (!subtree) {
        if ((*pbuf) && (!f_isoid(pbuf))){
	  free(cbuf);
          return NULL;
	}
        if (objid) {
          *nxtoid++ = subid;
          oidlen++;
          if (pbuf)
            oidlen += f_str2oid(nxtoid,pbuf,NMAX_SUBID - oidlen);
          *objidlen = oidlen;
        }
	free(cbuf);
        return (node);
      }
    }
    /* Salva no' corrente (e copia subid se for o caso) */
    if (objid) {
      *nxtoid++ = subid;
      oidlen++;
    }
    node = subtree;
    subtree = subtree->child_list;
  }
  if (objid)
    *objidlen = oidlen;

  free(cbuf);
  return (node);

}


/*-----------------------------------------------------------------------------
 * f_var2mibnode
 *
 * Convert a Lua given variable to an OID.
 * Obtem o ponteiro para o no e o oid (formato CMU) correspondente a uma
 * variavel lua   (string ou vbind)
 *----------------------------------------------------------------------------*/
struct snmp_mib_tree *f_var2mibnode(lua_State *L, oid *objid, int *objidlen) {
  char *s;
  if (lua_istable(L, -1)) {
    lua_pushstring(L, "oid");
    lua_gettable(L, -2);
    if (!lua_isstring(L, -1)){
      lua_remove(L, -1);
      return NULL;
    }
    s = (char *) lua_tostring(L, -1);
    lua_remove(L, -1);
  } else {
    if (!lua_isstring(L, -1))
      return NULL;
    s = (char *) lua_tostring(L, -1);
  }
  return(f_getmibnode(s,objid,objidlen));
}


/*-----------------------------------------------------------------------------
 * f_prim_err
 *
 * Traduz um codigo de erro retornado pela biblioteca CMU para o
 * codigo equivalente utilizado pelas primitivas SNMP
 *----------------------------------------------------------------------------*/

static Tsnmperr nm_snmp_errs[] = {
                                   {SNMP_ERR_NOERROR,NM_SNMP_NOERROR,FALSE},
                                   {SNMP_ERR_TOOBIG,NM_SNMP_TOOBIG,FALSE},
                                   {SNMP_ERR_NOSUCHNAME,NM_SNMP_NOSUCHNAME,FALSE},
                                   {SNMP_ERR_BADVALUE,NM_SNMP_BADVALUE,FALSE},
                                   {SNMP_ERR_READONLY,NM_SNMP_READONLY,FALSE},
                                   {SNMP_ERR_GENERR,NM_SNMP_GENERR,FALSE},

                                   {SNMP_ERR_NOACCESS,NM_SNMP_NOACCESS,FALSE},
                                   {SNMP_ERR_WRONGTYPE,NM_SNMP_WRONGTYPE,FALSE},
                                   {SNMP_ERR_WRONGLENGTH,NM_SNMP_WRONGLENGTH,FALSE},
                                   {SNMP_ERR_WRONGENCODING,NM_SNMP_WRONGENCODING,FALSE},
                                   {SNMP_ERR_WRONGVALUE,NM_SNMP_WRONGVALUE,FALSE},
                                   {SNMP_ERR_NOCREATION,NM_SNMP_NOCREATION,FALSE},
                                   {SNMP_ERR_INCONSISTENTVALUE,NM_SNMP_INCONSISTENTVALUE,FALSE},
                                   {SNMP_ERR_RESOURCEUNAVAILABLE,NM_SNMP_RESOURCEUNAVAILABLE,FALSE},
                                   {SNMP_ERR_COMMITFAILED,NM_SNMP_COMMITFAILED,FALSE},
                                   {SNMP_ERR_UNDOFAILED,NM_SNMP_UNDOFAILED,FALSE},
                                   {SNMP_ERR_AUTHORIZATIONERROR,NM_SNMP_AUTHORIZATIONERROR,FALSE},
                                   {SNMP_ERR_NOTWRITABLE,NM_SNMP_NOTWRITABLE,FALSE},
                                   {SNMP_ERR_INCONSISTENTNAME,NM_SNMP_INCONSISTENTNAME,FALSE},

                                   {SNMPERR_GENERR,NM_SNMP_GENERR,FALSE},
                                   {SNMPERR_BAD_LOCPORT,NM_SNMP_GENERR,FALSE},
                                   {SNMPERR_BAD_ADDRESS,NM_SNMP_BADPEER,FALSE},
                                   {SNMPERR_BAD_SESSION,NM_SNMP_BADSESSION,FALSE},
                                   {SNMPERR_TOO_LONG,NM_SNMP_GENERR,TRUE}
                                 };

int f_prim_err(int cod_cmu) {
  register Tsnmperr *nxt;
  for (nxt=nm_snmp_errs;;nxt++) {
    if (cod_cmu == nxt->cmu_err)
      return nxt->prim_err;
    if (nxt->last)
      return NM_SNMP_GENERR;
  }
  return NM_SNMP_GENERR;
}


/*-----------------------------------------------------------------------------
 * f_prim_type
 *
 *      Traduz um codigo de tipo retornado pela biblioteca CMU para o
 *      codigo equivalente utilizado pelas primitivas SNMP
 *----------------------------------------------------------------------------*/
#define SMI_NOSUCHOBJECT SNMP_NOSUCHOBJECT
#define SMI_NOSUCHINSTANCE SNMP_NOSUCHINSTANCE
#define SMI_ENDOFMIBVIEW SNMP_ENDOFMIBVIEW

static Tsnmptype nm_snmp_types[] = {
                                     {ASN_OBJECT_ID, NM_TYPE_OBJID,FALSE},
                                     {ASN_OCTET_STR, NM_TYPE_OCTETSTR,FALSE},
                                     {ASN_INTEGER,   NM_TYPE_INTEGER,FALSE},
                                     {ASN_IPADDRESS, NM_TYPE_IPADDR,FALSE},
                                     /* NETADDR deve estar abaixo de IPADDR */
                                     {ASN_IPADDRESS, NM_TYPE_NETADDR,FALSE},
                                     {ASN_COUNTER, NM_TYPE_COUNTER,FALSE},
                                     {ASN_GAUGE,   NM_TYPE_GAUGE,FALSE},
                                     {ASN_TIMETICKS, NM_TYPE_TIMETICKS,FALSE},
                                     {ASN_OPAQUE,    NM_TYPE_OPAQUE,FALSE},
                                     {ASN_NULL,      NM_TYPE_NULL,FALSE},
                                     {ASN_COUNTER64, NM_TYPE_COUNTER64,FALSE},
				     {ASN_OPAQUE_COUNTER64, NM_TYPE_COUNTER64, FALSE},

                                     /* Esses tipos nao valem para bib nova. Ver como fazer para mata-los !!! */
                                     {ASN_OCTET_STR, NM_TYPE_BITSTRING, FALSE},
                                     {ASN_OCTET_STR, NM_TYPE_NSAPADDR,  FALSE},
                                     {ASN_INTEGER,   NM_TYPE_UINTEGER,  FALSE},

				     /* Special opaque types */
                                     {ASN_APP_OPAQUE,     NM_TYPE_APP_OPAQUE, FALSE},
				     {ASN_OPAQUE_FLOAT,   NM_TYPE_FLOAT,      FALSE},
				     {ASN_OPAQUE_DOUBLE,  NM_TYPE_DOUBLE,     FALSE},
				     {ASN_OPAQUE_I64,     NM_TYPE_INTEGER64,  FALSE},
				     {ASN_OPAQUE_U64,     NM_TYPE_UNSIGNED64,  FALSE},

                                     /* DISPLAY nao deve estar antes de OCTET STRING */
                                     {ASN_OCTET_STR, NM_TYPE_DISPLAY,FALSE},

                                     {SNMP_NOSUCHOBJECT,   NM_SNMP_NOSUCHOBJECT,FALSE},
                                     {SNMP_NOSUCHINSTANCE, NM_SNMP_NOSUCHINSTANCE,FALSE},
                                     {SNMP_ENDOFMIBVIEW,   NM_SNMP_ENDOFMIBVIEW,TRUE}
                                   };

static int f_prim_type(u_char cod_cmu) {
  register Tsnmptype *nxt;
  for (nxt=nm_snmp_types;;nxt++) {
    if (cod_cmu == nxt->cmu_type)
      return nxt->prim_type;
    if (nxt->last)
      return NM_TYPE_OTHER;
  }
  return NM_TYPE_OTHER;
}

/*-----------------------------------------------------------------------------
 * f_cmu_type
 *
 * Convert Lua coded type into snmp type.
 *
 *      Traduz um codigo de tipo utilizado pelas primitivas SNMP para o
 * codigo equivalente utilizado pela biblioteca CMU
 *----------------------------------------------------------------------------*/

static u_char f_cmu_type(int cod_lua) {
  register Tsnmptype *nxt;
  for (nxt=nm_snmp_types;;nxt++) {
    if (cod_lua == nxt->prim_type)
      return nxt->cmu_type;
    if (nxt->last)
      return 0;
  }
  return 0;
}

/*-----------------------------------------------------------------------------
 * f_create_counter64
 *
 * Create a counter64 instance and push it on the stack.
 *----------------------------------------------------------------------------*/
int f_create_counter64(lua_State *L, struct counter64 val) {
  c64_new(L, val);
  return 1;
}
/*-----------------------------------------------------------------------------
 * f_create_time_table
 *
 * Create a time table from ticks, return table on stack.
 * Cria uma tabela do tipo timeticks
 *----------------------------------------------------------------------------*/

int f_create_time_table(lua_State *L, u_long timeticks) {
  int nxtval;

  lua_newtable(L);

  lua_pushstring(L, "ticks");
  lua_pushnumber(L, timeticks);
  lua_settable(L, -3);

  nxtval = timeticks % 100; /* deci-seconds */
  timeticks /= 100;

  lua_pushstring(L, "deciseconds");
  lua_pushnumber(L, nxtval);
  lua_settable(L,-3);

  nxtval = timeticks % 60; /* seconds */
  timeticks /= 60;

  lua_pushstring(L, "seconds");
  lua_pushnumber(L, nxtval);
  lua_settable(L, -3);

  nxtval = timeticks % 60; /* minutes */
  timeticks /= 60;

  lua_pushstring(L, "minutes");
  lua_pushnumber(L, nxtval);
  lua_settable(L, -3);

  nxtval = timeticks % 24; /* hours */
  timeticks /= 24;

  lua_pushstring(L, "hours");
  lua_pushnumber(L, nxtval);
  lua_settable(L, -3);

  lua_pushstring(L, "days");
  lua_pushnumber(L, timeticks);
  lua_settable(L, -3);

  return 1;
}

/*-----------------------------------------------------------------------------
 * f_create_vb
 *
 * Create a varbind. Returns a table on the stack.
 * Cria um vbind a partir de uma var CMU
 *----------------------------------------------------------------------------*/

int f_create_vb(lua_State *L, struct variable_list *var) {
  register u_char *pbuf;
  register u_char *pval;
  int vtype;
  char strbuf[2048]; /* mas que exagero */
  int is_hex,ind;

  pbuf = (u_char *) strbuf;
  lua_newtable(L);

  /* Primeiro vamos colocar o OID */
  f_oid2str(var->name,var->name_length,strbuf);
  lua_pushstring(L, "oid");
  lua_pushstring(L, strbuf);
  lua_settable(L, -3);

  /* Vamos tratar cada valor conforme seu tipo */
  vtype = f_prim_type(var->type);

  switch (vtype) {
  case NM_TYPE_OBJID:
    f_oid2str(var->val.objid,(var->val_len / sizeof(oid)),strbuf);
    lua_pushstring(L, "value");
    lua_pushstring(L, strbuf);
    break;

  case NM_TYPE_OCTETSTR:
  case NM_TYPE_OPAQUE:

    /* Isso nao vai acontecer, nova bib cmu nao trata */
  case NM_TYPE_BITSTRING:  /* ??? */
  case NM_TYPE_NSAPADDR: /* ??? */

    strbuf[0]=0;
    if (var->val_len != 0) {
      /* Primeiro vamos tentar uma string "comum" */
      if (vtype == NM_TYPE_OCTETSTR) {
        is_hex = FALSE;
        pbuf = (u_char *) strbuf;
        pval = var->val.string;
        for (ind = 0; ind < var->val_len ; ind++) {
          if ((!isprint(*pval)) && (*pval != 0x0a) && (*pval != 0x0d)) {
            is_hex = TRUE;
            break;
          }
          *pbuf++ = *pval++;
        }
      } else
        is_hex = TRUE;
      if (is_hex) {
        pbuf = (u_char *) strbuf;
        pval = var->val.string;
        for (ind = 0; ind < var->val_len; ind++) {
          sprintf((char *) pbuf,"%02hx:",(unsigned short)*pval++);
          pbuf += strlen((char *)pbuf);
        }
        pbuf--;
      } else
        vtype = NM_TYPE_DISPLAY;
      *pbuf = 0;
    }
    lua_pushstring(L, "value");
    lua_pushstring(L, strbuf);
    break;

  case NM_TYPE_INTEGER:
  case NM_TYPE_COUNTER:
  case NM_TYPE_GAUGE:

    /* Esse tipo nao e' tratado pela nova bib cmu */
  case NM_TYPE_UINTEGER:
    lua_pushstring(L, "value");
    lua_pushnumber(L, *(var->val.integer));
    break;

  case NM_TYPE_NETADDR:
  case NM_TYPE_IPADDR:
    pval = var->val.string;
    sprintf(strbuf,"%d.%d.%d.%d",pval[0],pval[1],pval[2],pval[3]);
    lua_pushstring(L, "value");
    lua_pushstring(L, strbuf);
    break;

  case NM_TYPE_TIMETICKS: 
    lua_pushstring(L, "value");
    f_create_time_table(L, *(var->val.integer));
    break;
    
  case NM_TYPE_COUNTER64:
  case NM_TYPE_UNSIGNED64:
    {
      lua_pushstring(L, "value");
      c64_new(L, *(var->val.counter64));
      break;
    }
  case NM_TYPE_INTEGER64:
    {
      lua_pushstring(L, "value");
      c64_new(L, *(var->val.counter64));
      break;
    }
  case NM_TYPE_FLOAT:
    lua_pushstring(L, "value");
    lua_pushnumber(L, *(var->val.floatVal));
    break;

  case NM_TYPE_DOUBLE:
    lua_pushstring(L, "value");
    lua_pushnumber(L, *(var->val.doubleVal));
    break;

  default:
    lua_pushstring(L, "value");
    lua_pushnil(L);
    break;
  }
  lua_settable(L, -3);

  /* Por fim coloca o tipo no vbind */
  lua_pushstring(L, "type");
  lua_pushnumber(L, vtype);
  lua_settable(L, -3);
  
  /* Attach the vbindmetatable to this varbind */
  lua_pushlightuserdata(L, &vbindmetatable);
  lua_gettable(L, LUA_REGISTRYINDEX);
  lua_setmetatable(L, -2);
  return 1;
}


/*-----------------------------------------------------------------------------
 * f_create_vbind
 *
 * Create a varbind list. Returns a table containing single varbinds.
 *    Controi um vbind LUA (resposta a oper. SNMP) a partir de variable_list CMU
 *----------------------------------------------------------------------------*/

int f_create_vbind(lua_State *L, int islist,struct variable_list *varlist) {
  int nextvb = 1;
  struct variable_list *nxtvar;
  int retval;

  /* O tipo de retorno (vb ou lista) depende da chamada */
  if (!islist) {
    retval = f_create_vb(L, varlist);
    return retval;
  } else {
    lua_newtable(L);
    for (nxtvar = varlist ; nxtvar ; nextvb++, nxtvar = nxtvar->next_variable) {
      f_create_vb(L, nxtvar);
      lua_rawseti(L, -2, nextvb);
    }
    return 1;
  }
}

/*-----------------------------------------------------------------------------
 * f_format_time
 *
 * Obtain snmp time value from Lua table.
 *
 * Obtem valor "cmu" correspondente a uma tabela do tipo timeticks
 *----------------------------------------------------------------------------*/

int f_format_time(lua_State *L, u_long *timeticks) {

  u_long tmptime = 0;

  /* Se tem ticks definido, usa este valor */
  lua_pushstring(L, "ticks");
  lua_gettable(L, -2);
  if (lua_isnumber(L, -1)) {
    *timeticks = lua_tonumber(L, -1);
    return 1;
  }
  lua_remove(L,-1);
  
  lua_pushstring(L, "days");
  lua_gettable(L, -2);
  if (!lua_isnil(L, -1)) {
    if (!lua_isnumber(L, -1))
      return 0;
    tmptime = lua_tonumber(L,-1);
    tmptime *= 24;   /* tempo esta' em horas */
  }
  lua_remove(L, -1);

  lua_pushstring(L, "hours");
  lua_gettable(L, -2);
  if (!lua_isnil(L,-1)) {
    if (!lua_isnumber(L, -1))
      return 0;
    tmptime += lua_tonumber(L,-1);
  }
  lua_remove(L,-1);
  if (tmptime)
    tmptime *= 60;   /* tempo esta' em minutos */

  lua_pushstring(L, "minutes");
  lua_gettable(L, -2);
  if (!lua_isnil(L,-1)) {
    if (!lua_isnumber(L, -1))
      return 0;
    tmptime += lua_tonumber(L, -1);
  }
  lua_remove(L, -1);
  if (tmptime)
    tmptime *= 60;   /* tempo esta' em segundos */


  lua_pushstring(L, "seconds");
  lua_gettable(L,-2);
  if (!lua_isnil(L, -1)) {
    if (!lua_isnumber(L,-1))
      return 0;
    tmptime += lua_tonumber(L, -1);
  }
  lua_remove(L,-1);
  if (tmptime)
    tmptime *= 100;   /* tempo esta' em centesimos de segundos */

  lua_pushstring(L, "decisecondes");
  lua_gettable(L, -2);
  if (!lua_isnil(L, -1)) {
    if (!lua_isnumber(L, -1))
      return 0;
    tmptime += lua_tonumber(L, -1);
  }
  lua_remove(L, -1);

  *timeticks = tmptime;
  return 1;
}

/*-----------------------------------------------------------------------------
 * f_create_vl
 *
 * Cria uma var CMU a partir de tipo + valor "lua"
 *----------------------------------------------------------------------------*/

struct variable_list *f_create_vl(lua_State *L, int prim_type) {
  struct variable_list *vlist;
  char strbuf[2048];   /* mas que exagero */
  char *strval;
  int len;
  int slen;

  /* Vamos tratar cada valor conforme seu tipo */

  switch (prim_type) {
  case NM_TYPE_OBJID:
    if (!lua_isstring(L, -1))
      return NULL;
    strval = (char *) lua_tostring(L, -1);
    if (!f_isoid(strval))
      return NULL;
    len = f_str2oid((oid *)strbuf, strval, NMAX_SUBID);
    len *= sizeof(oid);
    break;

  case NM_TYPE_OCTETSTR:
  case NM_TYPE_DISPLAY:
  case NM_TYPE_OPAQUE:

    /* Esses dois vao morrer ... vao como octet string */
  case NM_TYPE_BITSTRING:
  case NM_TYPE_NSAPADDR:

    if (!lua_isstring(L, -1))
      return NULL;
    strval = (char *)lua_tostring(L, -1);
#if LUA_VERSION_NUM > 501 
    slen = luaL_len(L, -1);
#else
    slen = lua_strlen(L, -1);
#endif
    /* Primeiro vamos verificar se e' uma "hex string" */
    if (prim_type != NM_TYPE_DISPLAY) {
      char *pstr = strval;
      u_char *pbuf = (u_char *)strbuf;
      unsigned short tmp;
      
      len = 0;
      for ( ; *pstr && slen > 0; pstr += 3, slen -=3 ) {
        if ((!isxdigit(*pstr)) || (!isxdigit(*(pstr+1))))
          break;
        if ((*(pstr+2)) && (*(pstr+2) != ':'))
          break;
        sscanf(pstr,"%2hx",&tmp);
        *pbuf++ = (u_char) tmp;
        len++;
      }
      if ( (*pstr == '\0') || (slen < 0))
        break;

      if (prim_type != NM_TYPE_OCTETSTR)
        return NULL;
    }

    /* E' para copiar a string do jeito que esta' */
    strcpy(strbuf, strval);
    len = strlen(strbuf);
    break;

  case NM_TYPE_INTEGER:
  case NM_TYPE_COUNTER:
  case NM_TYPE_GAUGE:
    if (!lua_isnumber(L, -1))
      return NULL;
    *((long *) strbuf) = (int) lua_tonumber(L, -1);
    len = sizeof(long);
    break;

    /* Esse tipo a bib nova CMU nao suporta, ira' como INT */
  case NM_TYPE_UINTEGER:
    if (!lua_isnumber(L, -1))
      return NULL;
    *((unsigned long *) strbuf) = (unsigned int) lua_tonumber(L, -1);
    len = sizeof(long);
    break;

  case NM_TYPE_NETADDR:
  case NM_TYPE_IPADDR:
    if (!lua_isstring(L, -1))
      return NULL;
    strval = (char *)lua_tostring(L, -1);
    if ((*((uint32_t *) strbuf) = inet_addr(strval)) == -1)
      return NULL;
    len = sizeof(long);
    break;

  case NM_TYPE_TIMETICKS:
    if (!lua_istable(L, -1))
      return NULL;
    if (!f_format_time(L, (unsigned long *)strbuf))
      return NULL;
    len = sizeof(long);
    break;

  case NM_TYPE_COUNTER64:
  case NM_TYPE_UNSIGNED64:
  case NM_TYPE_INTEGER64:
    {
      struct counter64 *var = (struct counter64*) strbuf;
      struct counter64 val = c64_get(L, -1);
      len = sizeof(struct counter64);
      *(&var->high) = val.high;
      *(&var->low) = val.low;
      break;
    }

  case NM_TYPE_FLOAT:
    if (!lua_isnumber(L, -1))
      return NULL;
    *((float *) strbuf) = (float) lua_tonumber(L, -1);
    len = sizeof(float);
    break;

  case NM_TYPE_DOUBLE:
    if (!lua_isnumber(L, -1))
      return NULL;
    *((double *) strbuf) = (double) lua_tonumber(L, -1);
    len = sizeof(double);
    break;

  case NM_TYPE_NULL:
    len = 0;
    break ;

  case NM_SNMP_NOSUCHINSTANCE:
  case NM_SNMP_NOSUCHOBJECT:
  case NM_SNMP_ENDOFMIBVIEW:
    len = 0;
    break;

    len = 0;
    break;

  default:
    return NULL;
  }

  /* Aloca variable list e area para o valor */
  vlist = (struct variable_list *) malloc(sizeof(struct variable_list));
  memset((char *)vlist, 0, sizeof(struct variable_list));
  if (len)
    vlist->val.string = (u_char *) malloc(len);
  else
    vlist->val.string = NULL;

  /* Copia valor e seta o tamanho */
  vlist->val_len = len;
  memcpy((char *)vlist->val.string,strbuf,len);

  /* Seta o tipo com o valor usado pela bib CMU */
  vlist->type = f_cmu_type(prim_type);
  return vlist;
}

/*-----------------------------------------------------------------------------
 * f_create_vlist
 *
 * Create varbind list.
 *
 *	Constroi uma variable_list CMU a partir de um vbind lua
 *----------------------------------------------------------------------------*/
struct variable_list *f_create_vlist_from_objid(lua_State *L, oid *objid, int *objidlen, char *errs) 
{
  struct snmp_mib_tree *mib_node;
  int prim_type;
  struct variable_list *vlist;

  /* Primeiro traduz oid/nome string para oid cmu */
  if ((mib_node = f_var2mibnode(L, objid, objidlen)) == NULL) {
    strcpy(errs, "snmp: bad name");
    return NULL;
  }

  /* Process the type: Push the type on top of stack */
  lua_pushstring(L, "type");
  lua_gettable(L, -2);

  if (!lua_isnil(L, -1)) {
    /* type given - check it's type now */
    if (!lua_isnumber(L, -1)) {
      strcpy(errs, "snmp: bad type (1)");
      return NULL;
    }
    prim_type = lua_tonumber(L, -1);
  } else {
    /* no type given - take it from the node */
    prim_type = mib_node->type;
  }
  lua_remove(L, -1);

  if (!(nm_snmp_validtype(prim_type))) {
    sprintf(errs, "snmp: bad type (2) prim=%d", prim_type);
    /*    strcpy(errs, "snmp: bad type (2)"); */
    return NULL;
  } 

  /* Process the value: Push the value on top of stack */
  lua_pushstring(L, "value");
  lua_gettable(L, -2);
  if ((vlist = f_create_vl(L, prim_type)) == NULL ) {
    sprintf(errs, "snmp: bad value of type %d", prim_type);
    return NULL;
  }
  lua_remove(L, -1);
  /* Coloca o object id da variavel */
  vlist->name = (oid *) malloc(*objidlen * sizeof(oid));
  memcpy((char *)vlist->name,(char *)objid,*objidlen * sizeof(oid));
  vlist->name_length = *objidlen;

  vlist->next_variable = NULL;

  return(vlist);
}

/*-----------------------------------------------------------------------------
 * f_create_vlist
 *
 * Create varbind list.
 *
 *	Constroi uma variable_list CMU a partir de um vbind lua
 *----------------------------------------------------------------------------*/
#if 1
struct variable_list *f_create_vlist(lua_State *L, char *errs) {
  oid objid[NMAX_SUBID];
  int objidlen;
  return f_create_vlist_from_objid(L, objid, &objidlen, errs);
}

#else
struct variable_list *f_create_vlist(lua_State *L, char *errs) {
  oid objid[NMAX_SUBID];
  int objidlen;
  struct snmp_mib_tree *mib_node;
  int prim_type;
  struct variable_list *vlist;

  /* Primeiro traduz oid/nome string para oid cmu */
  if ((mib_node = f_var2mibnode(L, objid, &objidlen)) == NULL) {
    strcpy(errs, "snmp: bad name");
    return NULL;
  }

  /* Process the type: Push the type on top of stack */
  lua_pushstring(L, "type");
  lua_gettable(L, -2);

  if (!lua_isnil(L, -1)) {
    /* type given - check it's type now */
    if (!lua_isnumber(L, -1)) {
      strcpy(errs, "snmp: bad type");
      return NULL;
    }
    prim_type = lua_tonumber(L, -1);
  } else
    /* no type given - take it from the node */
    prim_type = mib_node->type;

  lua_remove(L, -1);

  if (!(nm_snmp_validtype(prim_type))) {
    strcpy(errs, "snmp: bad type");
    return NULL;
  }

  /* Process the value: Push the value on top of stack */
  lua_pushstring(L, "value");
  lua_gettable(L, -2);
  if ((vlist = f_create_vl(L, prim_type)) == NULL ) {
    strcpy(errs, "snmp: bad value");
    return NULL;
  }
  lua_remove(L, -1);
  /* Coloca o object id da variavel */
  vlist->name = (oid *) malloc(objidlen * sizeof(oid));
  memcpy((char *)vlist->name,(char *)objid,objidlen * sizeof(oid));
  vlist->name_length = objidlen;

  vlist->next_variable = NULL;

  return(vlist);
}
#endif
/*-----------------------------------------------------------------------------
 * f_uptime
 *
 * Retorna o valor de sysUpTime.0 para esta entidade SNMP, em centesimos
 *  de segundo.
 *
 * Deve ser chamada na inicializacao da bib luaman para inicializar
 *  este valor.
 *
 *----------------------------------------------------------------------------*/

u_long f_uptime(void) {
  static time_t boottime = 0;

  if (!boottime) {
    boottime = time((time_t *) NULL);
    return 0;
  }
  return ((time((time_t *) NULL) - boottime) * 100);
}


/*-----------------------------------------------------------------------------
 * f_create_infovl
 *
 * Constroi uma variable_list CMU contendo os valores de sysUpTime.0
 *   e snmpTrapOID.0 (sao os primeiros vbinds para inform request)
 *
 * Recebe string contendo o TrapOID
 *----------------------------------------------------------------------------*/

struct variable_list *f_create_infovl(char *trapOID) {
  oid tobjid[NMAX_SUBID];
  int tobjidlen;
  oid *op;
  struct variable_list *vlist, *vp;

  /* Primeiro tenta traduzir o TrapOID (usuario pode ter dado nome ou OID) */
  if (f_getmibnode(trapOID,tobjid,&tobjidlen) == NULL)
    return NULL;

  /* Aloca um vbind para sysUpTime e o preenche */
  vlist = vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));

  vp->name_length = UPTIME_LEN;
  vp->name = op = (oid *)calloc(1, sizeof(oid) * UPTIME_LEN);
  memcpy((char *)op, (char *)sysUpTimeOid,sizeof(oid) * UPTIME_LEN);

  vp->type = ASN_TIMETICKS;

  vp->val.integer = (long *)calloc(1, sizeof(long));
  vp->val_len = sizeof(long);
  *(vp->val.integer) = (long)f_uptime();

  /* Proximo vbind e' para snmpTrapOID */
  vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
  vp = vp->next_variable;


  vp->name_length = TRAPOID_LEN;
  vp->name = op =(oid *)calloc(1, (sizeof(oid) * TRAPOID_LEN));
  memcpy((char *)op, (char *)snmpTrapOid,sizeof(oid) * TRAPOID_LEN);

  vp->type = ASN_OBJECT_ID;

  vp->val_len = sizeof (oid) * tobjidlen;
  vp->val.objid = op = (oid *)calloc(1, vp->val_len);
  memcpy((char *)op ,(char *)tobjid, vp->val_len);

  vp->next_variable = NULL;

  return(vlist);
}


/*-----------------------------------------------------------------------------
 * f_trapconv
 *
 * Converte um Trap PDU v1 em um Trap PDU v2
 *
 * Insere no inicio da varbind list sysUpTime.0 e snmpTrapOID.0 e no 
 *   fim snmpTrapEnterprise.0
 *
 * Converte id traps padrao (coldStart, warmStart, etc...) p/ trapOID 
 *    equivalente na SNMPv2 MIB.
 *
 * TrapOID de trap especifica e' construido da seguinte forma :
 *   enterprise.0.specific.
 *
 * Coloca o end ip do cabecalho da trap como origem do PDU
 *----------------------------------------------------------------------------*/


void f_trapconv(struct snmp_pdu *pdu) {
  struct variable_list *vp, *vptrap;
  oid *op;

#ifdef LEUDEL
  /* Coloca o end ip do cab trap como origem do pdu */
  memcpy((char *)&(pdu->address), (char *)&(pdu->agent_addr),
         sizeof(pdu->address));
#endif

  /* Salva o vbind original do pdu */
  vptrap = pdu->variables;

  /* Aloca um vbind para sysUpTime e o preenche */
  vp = (struct variable_list *)calloc(1, sizeof(struct variable_list));

  vp->name_length = UPTIME_LEN;
  vp->name = op = (oid *)calloc(1, sizeof(oid) * UPTIME_LEN);
  memcpy((char *)op, (char *)sysUpTimeOid,sizeof(oid) * UPTIME_LEN);

  vp->type = TYPE_TIMETICKS;

  vp->val.integer = (long *)calloc(1, sizeof(long));
  vp->val_len = sizeof(unsigned int);
  *(vp->val.integer) = pdu->time;

  pdu->variables = vp;

  /* Proximo vbind e' para snmpTrapOID */
  vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
  vp = vp->next_variable;


  vp->name_length = TRAPOID_LEN;
  vp->name = op =(oid *)calloc(1, (sizeof(oid) * TRAPOID_LEN));
  memcpy((char *)op, (char *)snmpTrapOid,sizeof(oid) * TRAPOID_LEN);

  vp->type = TYPE_OBJID;

  switch (pdu->trap_type) {
    /* Tratamento para as traps "padrao" */

  case 0:   /* coldStart */
  case 1:   /* warmStart */
  case 2:   /* linkDown */
  case 3:   /* linkUp */
  case 4:   /* authentication Failure */
  case 5:   /* egpNeighborLoss */

    vp->val_len = sizeof(oid) * (STDTRAP_LEN);
    vp->val.objid = op = (oid *)calloc(1, vp->val_len);
    memcpy((char *)op, (char *)snmpStdTrapOid,vp->val_len);
    op[STDTRAP_LEN-1] = (oid) ((pdu->trap_type) + 1);
    break;

    /* Tratamento para traps especificas */

  default:

    vp->val_len = sizeof (oid) * (pdu->enterprise_length + 2);
    vp->val.objid = op = (oid *)calloc(1, vp->val_len);
    memcpy((char *)op ,(char *)pdu->enterprise,
           sizeof(oid) * pdu->enterprise_length);
    op += pdu->enterprise_length;
    *op++ = 0;
    *op = (oid) (pdu->specific_type);
    break;
  }

  /* Insere o vlist original apos este vbind */
  vp->next_variable = vptrap;

  /* Agora procura o fim da lista */
  while (vp->next_variable)
    vp = vp->next_variable;

  /* Insere no fim da lista um vbind para snmpTrapEnterprise */
  vp->next_variable = (struct variable_list *)calloc(1, sizeof(struct variable_list));
  vp = vp->next_variable;
  vp->next_variable = NULL;

  vp->name_length = TRAPENT_LEN;
  vp->name = op =(oid *)calloc(1, (sizeof(oid) * TRAPENT_LEN));
  memcpy((char *)op, (char *)snmpTrapEntOid,sizeof(oid) * TRAPENT_LEN);

  vp->type = TYPE_OBJID;
  vp->val_len = sizeof(oid) * pdu->enterprise_length;
  vp->val.objid = op = (oid *)calloc(1, vp->val_len);
  memcpy((char *)op ,(char *)pdu->enterprise,
         sizeof(oid) * pdu->enterprise_length);
}
#ifdef REMOVE_THIS
void f_setup_oid(oid * it, size_t * len, u_char * id, size_t idlen,
          const char *user)
{
  int i, itIndex = *len;
  
  *len = itIndex + 1 + idlen + 1 + strlen(user);
  
  it[itIndex++] = idlen;
  for (i = 0; i < (int) idlen; i++) {
    it[itIndex++] = id[i];
  }
  
  it[itIndex++] = strlen(user);
  for (i = 0; i < (int) strlen(user); i++) {
    it[itIndex++] = user[i];
  }
  
  /*
   * fprintf(stdout, "setup_oid: ");  
   */
  /*
   * fprint_objid(stdout, it, *len);  
   */
  /*
   * fprintf(stdout, "\n");  
   */
}
#endif
