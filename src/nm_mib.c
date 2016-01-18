/*-----------------------------------------------------------------------------
 * nm_mib.c
 *
 * Funcoes "C" utilizadas pelo conjunto de primitivas MIB.
 * Estas funcoes sao responsaveis pela interface com a biblioteca CMU-SNMP2
 *
 *----------------------------------------------------------------------------*/

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/mib_api.h>
#include <net-snmp/library/parse.h>

#ifndef WIN32
#include <sys/param.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <ctype.h>
#include <errno.h>

#include "lua.h"
#include "lauxlib.h"

#include "snmp.h"
#include "nm_mib.h"

#define MYNAME "mib"
#define MYVERSION "3.0"
#define MYDESCRIPTION "LUASNMP MIB access"

/*-----------------------------------------------------------------------------
 * Prototipos
 *----------------------------------------------------------------------------*/

int nm_mib_getname(char *buf, oid *objid, int objidlen, int full);


/*-----------------------------------------------------------------------------
 * Funcoes utilizadas pelas primitivas MIB
 *----------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
 * nm_mib_module
 *
 * Obtem o OID de uma variavel dado o seu nome.
 *
 *      Recebe na pilha LUA uma string com o nome da variavel.
 * Retorna codigo de erro e uma string com o OID (ou nil)
 *----------------------------------------------------------------------------*/
static int nm_mib_module(lua_State *L) {
  char *name;
  oid objid[NMAX_SUBID];
  int objidlen;
  struct module *mod;
  struct snmp_mib_tree *node = NULL;

  /* Get the name from Lua Stack */
  if (lua_isnil(L, -1) || (!lua_isstring(L, -1))) {
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }
  name = (char *) lua_tostring(L, -1);

  /* Traduz o nome para um OID */
  if ((node = f_getmibnode(name, objid, &objidlen)) == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }
  if ((mod = find_module(node->modid)) == NULL){
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such module");
    return 2;
  }
  lua_pushstring(L, mod->name);
  lua_pushstring(L, mod->file);
  return 2;
}
/*-----------------------------------------------------------------------------
 * nm_mib_oid
 *
 * Obtem o OID de uma variavel dado o seu nome.
 *
 *      Recebe na pilha LUA uma string com o nome da variavel.
 * Retorna codigo de erro e uma string com o OID (ou nil)
 *----------------------------------------------------------------------------*/

static int nm_mib_oid(lua_State *L) {
  char *name;
  oid objid[NMAX_SUBID];
  int objidlen;
  char oidbuf[2048]; /* exagerado !!! */

  /* Obtem o nome da pilha de lua */
  if (lua_isnil(L, -1) || (!lua_isstring(L, -1))) {
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }
  name = (char *) lua_tostring(L, -1);


  /* Testa se ja' e' um OID para poupar tempo */
  if (f_isoid(name)) {
    lua_pushstring(L, name);
    return 1;
  }

  /* Traduz o nome para um OID */
  if (f_getmibnode(name, objid, &objidlen) == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }
  f_oid2str(objid,objidlen,oidbuf);
  lua_pushstring(L, oidbuf);
  return 1;
}

/*-----------------------------------------------------------------------------
 *
 * nm_mib_name
 * nm_mib_fullname
 *
 * Obtem o nome (last ou full) de uma variavel dado o seu OID.
 *
 *      Recebe na pilha LUA uma string com o OID da variavel.
 * Retorna codigo de erro e uma string com o nome (ou nil)
 *
 *----------------------------------------------------------------------------*/

static int nm_mib_lfname(lua_State *L, int full);

static int nm_mib_name(lua_State *L) {
  return nm_mib_lfname(L, LAST_NAME);
}

static int nm_mib_fullname(lua_State *L) {
  return nm_mib_lfname(L, FULL_NAME);
}

static int nm_mib_lfname(lua_State *L, int full) {
  oid objid[NMAX_SUBID];
  int objidlen;
  char name[2048];
  char *str_oid;
  int res;

  /* Obtem o oid da pilha de lua */
  if (lua_isnil(L, -1) || (!lua_isstring(L, -1))){
    lua_pushnil(L);
    lua_pushnumber(L, NM_MIB_NOSUCHNAME);
    return 2;
  }
  str_oid = (char *) lua_tostring(L, -1);
  if (!f_getmibnode(str_oid,objid,&objidlen)) {
    if (f_isoid(str_oid)) {
      lua_pushstring(L, str_oid);
      return 1;
    }
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }

  /* Traduz o oid para um nome */
  res = nm_mib_getname(name,objid,objidlen,full);
  lua_pushstring(L, name);
  lua_pushnumber(L, res);
  return 2;
}

/*-----------------------------------------------------------------------------
 * nm_mib_description
 *
 * Obtem a descricao textual de uma variavel dado o seu OID.
 *
 *      Recebe na pilha LUA uma string com o nome/OID da variavel.
 * Retorna codigo de erro e uma string com a descricao (ou nil)
 *
 *----------------------------------------------------------------------------*/

static int nm_mib_description(lua_State *L) {
  struct snmp_mib_tree *node;
  oid objid[NMAX_SUBID];
  size_t objidlen;
  char vazio[] = {0};
  char *buf;
  int width;
  int buflen, outlen;

  /* Obtem o oid da pilha de lua */
  if (lua_isnil(L, 1) || (!lua_isstring(L, 1))){
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }

  width = luaL_optnumber(L, 2, 80);
  buflen = luaL_optnumber(L, 3, 512);
  
  /* Obtem a descricao da variavel */
  if ((node=f_getmibnode((char *) lua_tostring(L, 1), objid, (int *)&objidlen))) {
    buf = (char *) malloc(buflen*sizeof(char));
    outlen = snprint_description(buf, (size_t) buflen, objid, objidlen, width);
    if (outlen != 0)
      lua_pushstring(L, buf);
    else
      lua_pushstring(L, vazio);
    free(buf);
    return 1;
  } else {
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }
  return 1;
}

/*-----------------------------------------------------------------------------
 * nm_mib_type
 *
 * Obtem o tipo de uma variavel dado o seu OID.
 *
 *      Recebe na pilha LUA uma string com o OID da variavel.
 * Retorna codigo de erro e tipo (int) da variavel (ou nil)
 *
 *----------------------------------------------------------------------------*/
static const char *typetb[] = {
  "OTHER",
  "OBJECT IDENTIFIER",
  "OCTET STRING",
  "INTEGER",
  "NetworkAddress",
  "IpAddress",
  "Counter",
  "Gauge32",
  "TimeTicks",
  "Opaque",
  "NULL",
  "Counter64",
  "BIT STRING",
  "NsapAddress",
  "UInteger",
  "UInteger32",
  "Integer32",
  "",
  "",
  "",
  "TRAP-TYPE",
  "NOTIFICATION-TYPE"
  "OBJECT-GROUP",
  "NOTIFICATION-GROUP"
  "MODULE-IDENTITY"
  "AGENT-CAPABILITIES",
  "MODULE-COMPLIANCE",
};

static int nm_mib_type(lua_State *L) {
  struct snmp_mib_tree *mib_node;

  /* Obtem o oid da pilha de lua */
  if (lua_isnil(L, -1) || (!lua_isstring(L, -1))){
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }

  /* Obtem o tipo da variavel */
  if ((mib_node=f_getmibnode((char *) lua_tostring(L, -1),NULL,NULL))) {
    if (mib_node->type < 27){
      lua_pushnumber(L, mib_node->type);
      lua_pushstring(L, typetb[mib_node->type]);
      return 2;
    } else {
      lua_pushnumber(L, mib_node->type);
      switch(mib_node->type){
      case 120:
	lua_pushstring(L, "Opaque: Float");
	break;
      case 121:
	lua_pushstring(L, "Opaque: Double");
	break;
      case 122:
	lua_pushstring(L, "Opaque: Integer64");
	break;
      case 123:
	lua_pushstring(L, "Opaque: Unsigned64");
	break;
      case 128:
	lua_pushstring(L, "NO SUCH OBJECT");
	break;
      case 129:
	lua_pushstring(L, "NO SUCH INSTANCE");
	break;
      case 130:
	lua_pushstring(L, "END OF MIB VIEW");
	break;
      default:
	lua_pushstring(L, "");
	break;
      }
      return 2;
    }
  } else {
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }
}

/*-----------------------------------------------------------------------------
 * nm_mib_access
 *
 * Obtem o tipo de acesso de uma variavel dado o seu OID.
 *
 *      Recebe na pilha LUA uma string com o OID da variavel.
 * Retorna codigo de erro e tipo de acesso (string) da variavel (ou nil)
 *
 *----------------------------------------------------------------------------*/

static int nm_mib_access(lua_State *L) {
  struct snmp_mib_tree *mib_node;

  /* Obtem o oid da pilha de lua */
  if (lua_isnil(L, -1) || (!lua_isstring(L, -1))){
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }

  /* Obtem o tipo de acesso da variavel */
  if ((mib_node=f_getmibnode((char *) lua_tostring(L, -1),NULL,NULL))) {
    switch (mib_node->access) {
    case NM_MIB_NOACCESS:
      lua_pushliteral(L, "not-accessible");
      break;
    case NM_MIB_READONLY:
      lua_pushliteral(L, "read-only");
      break;
    case NM_MIB_READWRITE:
      lua_pushliteral(L, "read-write");
      break;
    case NM_MIB_WRITEONLY:
      lua_pushliteral(L, "write-only");
      break;
    case NM_MIB_READCREATE:
      lua_pushliteral(L, "read-create");
      break;
    default:
      lua_pushliteral(L, "not-accessible");
      break;
    }
    return 1;
  } else {
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }
}

/*-----------------------------------------------------------------------------
 * nm_mib_parent
 *
 * Obtem o OID da variavel parent de uma variavel, dado seu OID
 *
 *      Recebe na pilha LUA uma string com o OID da variavel.
 * Retorna codigo de erro e string OID do parent da variavel (ou nil)
 *
 *----------------------------------------------------------------------------*/

static int nm_mib_parent(lua_State *L) {
  oid objid[NMAX_SUBID];
  int objidlen;
  struct snmp_mib_tree *mib_node;
  char oidbuf[2048];

  /* Obtem o oid da pilha de lua */
  if (lua_isnil(L, -1) || (!lua_isstring(L, -1))){
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }

  /* Obtem o parent da variavel */
  if ((mib_node=f_getmibnode((char *) lua_tostring(L, -1),NULL,NULL))) {
    if (mib_node->parent) {
      objidlen = f_mibnode2oid(mib_node->parent,objid);
      f_oid2str(objid,objidlen,oidbuf);
      lua_pushstring(L, oidbuf);
      return 1;
    } else {
      lua_pushnil(L);
      lua_pushstring(L, "mib: end of mib");
      return 2;
    }
  } else {
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }
}


/*-----------------------------------------------------------------------------
 * nm_mib_successor
 *
 * Obtem os OIDs das variaveis filhas de uma variavel, dado seu OID
 *
 *      Recebe na pilha LUA uma string com o OID da variavel.
 * Retorna codigo de erro e tabela de strings c/ OIDs (ou nil)
 *
 *----------------------------------------------------------------------------*/

static int nm_mib_successor(lua_State *L) {
  oid objid[NMAX_SUBID];
  int objidlen, nxt;
  struct snmp_mib_tree *mib_node, *tp;
  char oidbuf[2048];

  /* Obtem o oid da pilha de lua */
  if (lua_isnil(L, -1) || (!lua_isstring(L, -1))){
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }

  /* Obtem os sucessores da variavel */
  if ((mib_node=f_getmibnode((char *) lua_tostring(L, -1),NULL,NULL))) {
    if (mib_node->child_list) {
      /* leu      suc_table = lua_createtable(); */
      lua_newtable(L);
      /* Como a bib CMU guardou os filhos ao contrario, vou inverter */
      tp = mib_node->child_list;
      nxt = 1;
      while ((tp = tp->next_peer))
        nxt++;

      for (mib_node = mib_node->child_list ; mib_node ;
           mib_node = mib_node->next_peer, nxt--) {
        objidlen = f_mibnode2oid(mib_node,objid);
        f_oid2str(objid,objidlen,oidbuf);
        lua_pushnumber(L, nxt);
        lua_pushstring(L, oidbuf);
	lua_settable(L, -3);
      }
      return 1;
    } else {
      lua_pushnil(L);
      lua_pushstring(L, "mib: end of mib");
      return 2;
    }
  } else {
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }
}
/*-----------------------------------------------------------------------------
 * nm_mib_enums
 *
 * Obtem a tabela de strings associadas ao valores de uma variavel
 *
 *      Recebe na pilha LUA uma string com o OID da variavel.
 * Retorna codigo de erro e uma tabela de strings (ou nil)
 *
 *----------------------------------------------------------------------------*/

static int nm_mib_enums(lua_State *L) {
  struct snmp_mib_tree *mib_node;
  struct enum_list *enums;
  char vazio[] = {0};

  /* Obtem o oid da pilha de lua */
  if (lua_isnil(L, -1) || (!lua_isstring(L, -1))){
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }

  /* Obtem o no da variavel */
  if (!(mib_node=f_getmibnode((char *) lua_tostring(L, -1),NULL,NULL))) {
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }
  if ((mib_node->type != TYPE_INTEGER) && (mib_node->type != TYPE_UINTEGER)) {
    lua_pushnil(L);
    lua_pushstring(L, "mib: bad type");
    return 2;
  }
  if (!(enums = mib_node->enums)) {
    return 0;
  }
  lua_newtable(L);
  for (; enums ; enums = enums->next) {
    lua_pushnumber(L, enums->value);
    if (enums->label)
      lua_pushstring(L, enums->label);
    else
      lua_pushstring(L, vazio);
    lua_settable(L, -3);
  }

  return 1;
}

/*-----------------------------------------------------------------------------
 * nm_mib_load
 *
 * Carrega definicoes de um arquivo e insere na arvore global
 *
 *      Recebe na pilha LUA uma string com o nome do arquivo
 * Retorna codigo de erro e, se for o caso, uma string descritiva do erro
 *
 *----------------------------------------------------------------------------*/

static int nm_mib_load(lua_State *L) {
  void *tree;
  /* Obtem o nome do arquivo da pilha de lua */
  if (lua_isnil(L, -1) || (!lua_isstring(L, -1))){
    lua_pushnumber(L, NM_MIB_BADFILE);
    lua_pushstring(L, "mib: invalid file name");
    return 2;
  }
  /*
  if ( read_newmib((char *) lua_tostring(L, -1),&strErr) ) {
  if (!add_mibfile((char *) lua_tostring(L, -1), NULL, NULL) ) {
  */
  if ((tree = (void *)read_mib((char *) lua_tostring(L, -1))) == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "mib: cannot add mib");
    return 2;
  } else {
    lua_pushlightuserdata(L, tree);
    return 1;
  }
}

/*-----------------------------------------------------------------------------
 * Get Default Value
 *----------------------------------------------------------------------------*/
static int nm_mib_default(lua_State *L) {
  struct snmp_mib_tree *mib_node;

  /* Obtem o oid da pilha de lua */
  if (lua_isnil(L, -1) || (!lua_isstring(L, -1))){
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }

  /* Obtem o tipo da variavel */
  if ((mib_node=f_getmibnode((char *) lua_tostring(L, -1),NULL,NULL))) {
    if (mib_node->defaultValue == NULL){
      return 0;
    } else {
      lua_pushstring(L, mib_node->defaultValue);
      return 1;
    }
  } else {
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }
}

/*-----------------------------------------------------------------------------
 * Get Units
 *----------------------------------------------------------------------------*/
static int nm_mib_units(lua_State *L) {
  struct snmp_mib_tree *mib_node;

  /* Obtem o oid da pilha de lua */
  if (lua_isnil(L, -1) || (!lua_isstring(L, -1))){
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }

  /* Obtem o tipo da variavel */
  if ((mib_node=f_getmibnode((char *) lua_tostring(L, -1),NULL,NULL))) {
    if (mib_node->units == NULL){
      return 0;
    } else {
      lua_pushstring(L, mib_node->units);
      return 1;
    }
  } else {
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }
}

/*-----------------------------------------------------------------------------
 * Get Augments
 *----------------------------------------------------------------------------*/
static int nm_mib_augments(lua_State *L) {
  struct snmp_mib_tree *mib_node;

  /* Obtem o oid da pilha de lua */
  if (lua_isnil(L, -1) || (!lua_isstring(L, -1))){
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }

  /* Obtem o tipo da variavel */
  if ((mib_node=f_getmibnode((char *) lua_tostring(L, -1),NULL,NULL))) {
    if (mib_node->augments == NULL){
      return 0;
    } else {
      lua_pushstring(L, mib_node->augments);
      return 1;
    }
  } else {
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }
}

#ifdef DOESNOTWORKINTREE
/*-----------------------------------------------------------------------------
 * Get Filename and line number
 *----------------------------------------------------------------------------*/
static int nm_mib_fileinfo(lua_State *L) {
  struct snmp_mib_tree *mib_node;
  char vazio[] = {0};
  int retval;

  /* Obtem o oid da pilha de lua */
  if (lua_isnil(L, -1) || (!lua_isstring(L, -1))){
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }

  /* Obtem o tipo da variavel */
  if ((mib_node=f_getmibnode((char *) lua_tostring(L, -1),NULL,NULL))) {
    if (mib_node->filename == NULL){
      lua_pushnil(L,vazio);
      lua_pushstring(L, "mib: no filename");
      return 2;
    } else {
      lua_pushstring(L, mib_node->filename);
      retval = 1;
      if (mib_node->lineno != NULL){
	lua_pushnumber(L, mib_node->lineno);
	retval++;
      } else {
	lua_pushnumber(L, -1);
	retval++;
      }
      return retval;
    }
  } else {
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }
}
#endif
/*-----------------------------------------------------------------------------
 * Get Indexes
 *----------------------------------------------------------------------------*/
static int nm_mib_indexes(lua_State *L) {
  struct snmp_mib_tree *mib_node;
  struct index_list *index;

  /* Obtem o oid da pilha de lua */
  if (lua_isnil(L, -1) || (!lua_isstring(L, -1))){
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }

  /* Obtem o tipo da variavel */
  if ((mib_node=f_getmibnode((char *) lua_tostring(L, -1),NULL,NULL))) {
    if (mib_node->indexes == NULL){
      return 0;
    } else {
      lua_newtable(L);
      for (index = mib_node->indexes; index; index = index->next){
	lua_pushstring(L, index->ilabel);
	lua_pushnumber(L, index->isimplied);
	lua_settable(L, -3);
      }
      return 1;
    }
  } else {
    lua_pushnil(L);
    lua_pushstring(L, "mib: no such name");
    return 2;
  }
}

/*-----------------------------------------------------------------------------
 * Funcoes de inicializacao
 *----------------------------------------------------------------------------*/


/*-----------------------------------------------------------------------------
 * nm_mib_init
 *
 * Inicializacao das primitivas
 *----------------------------------------------------------------------------*/

static int nm_mib_init(lua_State *L) {
  init_mib();
  return 0;
}

/*-----------------------------------------------------------------------------
 * nm_mib_register
 *
 * Registra as funcoes "C" chamadas pelas primitivas MIB
 *----------------------------------------------------------------------------*/
#if 0
static const luaL_reg funcs[] = {
#else
const luaL_Reg mibfuncs[] = {
#endif
  {"init", nm_mib_init},
  {"_load", nm_mib_load},
  {"oid", nm_mib_oid},
  {"name", nm_mib_name},
  {"module", nm_mib_module},
  {"fullname", nm_mib_fullname},
  {"description", nm_mib_description},
  {"enums", nm_mib_enums},
  {"type", nm_mib_type},
  {"access", nm_mib_access},
  {"parent", nm_mib_parent},
  {"successor", nm_mib_successor},
  {"default", nm_mib_default},
  {"units", nm_mib_units},
  {"indexes", nm_mib_indexes},
  {"augments", nm_mib_augments},
#ifdef DOESNOTWORKINTREE
  {"fileinfo", nm_mib_fileinfo},
#endif
  {NULL, NULL}
};

#if 0
LUALIB_API int luaopen_snmpmib(lua_State *L){
  luaL_openlib(L, MYNAME, funcs, 0);
  lua_pushliteral(L, "_VERSION");
  lua_pushliteral(L, MYVERSION);
  lua_settable(L, -3);
  lua_pushliteral(L, "_DESCRIPTION");
  lua_pushliteral(L, MYDESCRIPTION);
  lua_settable(L, -3);
  return 1;
}
#endif
/*-----------------------------------------------------------------------------
 * Funcoes internas e auxiliares
 *----------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
 *   nm_mib_getname
 *
 * Dado um oid recupera o nome da variavel
 *----------------------------------------------------------------------------*/
int nm_mib_getname(char *buf, oid *objid, int objidlen, int full) {
  struct snmp_mib_tree *subtree = Mib;
  struct snmp_mib_tree *last_tree = NULL;

  /* Procura o proximo nome */
  for (; objidlen; objid++, objidlen--) {
    for (; subtree; subtree = subtree->next_peer) {
      if ( *objid == subtree->subid ) {
        /* Copia se e' full name ou ultimo subid */
        if ( (full) || (objidlen == 1) ) {
          strcpy (buf,subtree->label);
          if (objidlen > 1) {
            while (*buf)
              buf++;
            *buf++ = '.';
          }
        } else
          last_tree = subtree;
        break;
      }
    }
    /* Nao consegui traduzir a partir deste subid */
    if (!subtree) {
      if (last_tree) {
        strcpy(buf,last_tree->label);
        while (*buf)
          buf++;
        *buf++ = '.';
      }
      for (; objidlen > 1; objidlen--) {
        sprintf(buf,"%u.",(unsigned int) *objid++);
        while (*buf)
          buf++;
      }
      sprintf(buf,"%u",(unsigned int) *objid);
      return 0;
    }
    subtree = subtree->child_list;
  }
  return 1;
}
