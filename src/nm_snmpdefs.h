/*
 * nm_snmpdefs.h
 *
 *	Definicoes utilizados pelas primitivas SNMP
 *
 *	ATENCAO : MANTER CONSISTENCIA COM LUA !!!
 *
 */


#ifndef nm_snmpdefs_h
#define	nm_snmpdefs_h

/*
 * Parametros de configuracao de uma sessao SNMP
 */

#define	NM_SNMPv1	1
#define	NM_SNMPv2C	2
#define	NM_SNMPv2	3
#define NM_SNMPv3       4

/*
 * Codigos de erro
 *
 */

/* 
 * PDU error status
 */

/* SNMPv1 */
#define	NM_SNMP_NOERROR		0
#define	NM_SNMP_TOOBIG		1
#define	NM_SNMP_NOSUCHNAME	2
#define	NM_SNMP_BADVALUE	3
#define	NM_SNMP_READONLY	4
#define	NM_SNMP_GENERR		5

/* SNMPv2 */
#define	NM_SNMP_NOACCESS	6
#define	NM_SNMP_WRONGTYPE	7
#define	NM_SNMP_WRONGLENGTH	8
#define	NM_SNMP_WRONGENCODING	9
#define	NM_SNMP_WRONGVALUE	10
#define	NM_SNMP_NOCREATION	11
#define	NM_SNMP_INCONSISTENTVALUE	12
#define	NM_SNMP_RESOURCEUNAVAILABLE	13
#define	NM_SNMP_COMMITFAILED		14
#define	NM_SNMP_UNDOFAILED		15
#define	NM_SNMP_AUTHORIZATIONERROR	16
#define	NM_SNMP_NOTWRITABLE		17
#define	NM_SNMP_INCONSISTENTNAME	18

/*
 * Erros LuaMan
 */

/* Erros em parametros de configuracao de sessoes */

#define	NM_SNMP_BADVERSION	101
#define	NM_SNMP_BADCOMMUNITY	102
#define	NM_SNMP_BADTIME		103
#define	NM_SNMP_BADRETRIES	104
#define	NM_SNMP_BADPEER		105
#define	NM_SNMP_BADPORT		106
#define	NM_SNMP_BADCALLBACK	107
#define	NM_SNMP_BADTRAP		108
#define	NM_SNMP_BADINFO		109
#define	NM_SNMP_INVINFO		110

/* Erros em parametros p/ operacoes SNMP */

#define	NM_SNMP_BADSESSION	120
#define	NM_SNMP_BADTYPE		121
#define	NM_SNMP_BADNAME		NM_SNMP_NOSUCHNAME

#define	NM_SNMP_BADNR		123
#define	NM_SNMP_BADMR		124

#define	NM_SNMP_INVINFOREQ	125
#define	NM_SNMP_BADTRAPOID	126

/* Outros */

#define	NM_SNMP_TIMEOUT		190
#define	NM_SNMP_INTERR		191


/*
 * Tipos de request
 */

#define	NM_SNMP_GET_REQ		1
#define	NM_SNMP_GETNEXT_REQ	2
#define	NM_SNMP_SET_REQ		3

#define	NM_SNMP_BULK_REQ	5
#define	NM_SNMP_INFO_REQ	6

/*
 * Modos de request
 */

#define	NM_SNMP_SYNCH_REQ	0
#define	NM_SNMP_ASYNCH_REQ	1

#endif
