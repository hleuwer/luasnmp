/*-----------------------------------------------------------------------------
 * nm_init.c
 *
 *	Inicializacao e registro das funcoes "C" utilizadas pelos conjuntos
 *	de primitivas da API de gerenciamento.
 *
 *----------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>

#include "lua.h"
#include "lualib.h"



/* Funcoes para o registro das funcoes de cada conjunto */
extern void nm_snmp_register(void);
extern void nm_snmp_init(char *binp, char *straps);
extern void nm_mib_register(void);
extern void nm_mib_init(char *mibf);

#ifndef WIN32
extern void RegisterDns();
extern void RegisterDb();
extern void RegisterIcmp();
extern void RegisterSyslog();
extern void RegisterCrontab();
#endif

void nm_file_load(char *path, char *file)
{
  int result;
  char lua_path[256];
  sprintf(lua_path,"%s/%s",path,file);
  if ((result=lua_dofile(lua_path)))
  {
    if (result == 2)
      fprintf(stderr,"\nLUAMAN : error loading %s\n\n",lua_path);
    exit(2);
  }
}

void nm_initialize(char *binp, char *mibf, char *straps)
{
  /* Inicializacao da biblioteca lua */
  strlib_open();

  /* Registra funcoes do conjunto MIB */
  nm_mib_init(mibf);
  nm_mib_register();

  /* Registra funcoes do conjunto SNMP */
  nm_snmp_init(binp,straps);
  nm_snmp_register();

#ifndef WIN32
  /* Registra as funcoes dos outros conjuntos */
  RegisterDns();
  RegisterDb();
  RegisterIcmp();
  RegisterSyslog();
  RegisterCrontab();
#endif


  /* Carrega as funcoes LUA */

  nm_file_load(binp,"luaman.lua");
}

void nm_init()
{
    char *BIN_PATH, *MIBF, *STRAPS, *getenv();

    BIN_PATH = getenv("LUAMAN_BIN");
    if (!BIN_PATH)
    {
      fprintf(stderr,"\nLUAMAN: LUAMAN_BIN not defined\n\n");
      exit(2);
    }
    MIBF = getenv("MIBFILE");

    STRAPS = getenv("STRAPS");


    nm_initialize(BIN_PATH,MIBF,STRAPS);
}

#ifndef WIN32
void nm_initc()
{
    char MIBF[] = "/home/ieponda/edison/public_html/projeto/mib/mib.txt";
    char BIN_PATH[] = "/home/ieponda/edison/luaman/bin";
    char STRAPS[] = "/home/ieponda/edison/luaman/bin/straps";

    nm_initialize(BIN_PATH, MIBF, STRAPS);
}
#endif
