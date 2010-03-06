/*
 * nm_mibdefs.h
 *
 *	Definicoes utilizados pelas primitivas MIB
 *
 *	ATENCAO : MANTER CONSISTENCIA COM LUA !!!
 *
 */


#ifndef nm_mibdefs_h
#define	nm_mibdefs_h

#include <net-snmp/library/parse.h>

/*
 * Codigos de erro
 */

#define	NM_MIB_NOERROR		200
#define	NM_MIB_BADTYPE		201
#define	NM_MIB_NOSUCHNAME	202
#define	NM_MIB_ENDOFMIB		203
#define	NM_MIB_BADFILE		204

/*
 * Tipos de acesso a uma variavel
 */

#define	NM_MIB_NOACCESS		MIB_ACCESS_NOACCESS
#define	NM_MIB_READONLY		MIB_ACCESS_READONLY
#define	NM_MIB_READWRITE	MIB_ACCESS_READWRITE
#define	NM_MIB_WRITEONLY	MIB_ACCESS_WRITEONLY
#define	NM_MIB_READCREATE	MIB_ACCESS_CREATE
#define NM_MIB_CREATE           MIB_ACCESS_CREATE


#endif
