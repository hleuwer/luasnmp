/*
 * nm_varbind.h
 *
 *	Definicoes relativas a varbinds 
 *	 utilizados pelas primitivas MIB e SNMP
 *
 *	ATENCAO : MANTER CONSISTENCIA COM LUA !!!
 *
 */


#ifndef nm_varbind_h
#define	nm_varbind_h

/*
 * Data Types
 */

#define NM_TYPE_OTHER          0
#define NM_TYPE_OBJID          1
#define NM_TYPE_OCTETSTR       2
#define NM_TYPE_INTEGER        3
#define NM_TYPE_NETADDR        4
#define NM_TYPE_IPADDR         5
#define NM_TYPE_COUNTER        6
#define NM_TYPE_GAUGE          7
#define NM_TYPE_TIMETICKS      8
#define NM_TYPE_OPAQUE         9
#define NM_TYPE_NULL           10
#define NM_TYPE_COUNTER64      11
#define NM_TYPE_BITSTRING      12
#define NM_TYPE_NSAPADDRESS    13
#define NM_TYPE_UINTEGER       14
#define NM_TYPE_UNSIGNED32     15
#define NM_TYPE_INTEGER32      16

#define NM_TYPE_SIMPLE_LAST    16

#define NM_TYPE_TRAP_TYPE      20
#define NM_TYPE_NOTIF_TYPE     21
#define NM_TYPE_OBJGROUP       22
#define NM_TYPE_NOTIFGROUP     23
#define NM_TYPE_MODID	       24
#define NM_TYPE_AGENTCAP       25
#define NM_TYPE_MODCOMP        26

#define NM_TYPE_APP_OPAQUE     0x70
#define NM_TYPE_FLOAT          120
#define NM_TYPE_DOUBLE         121
#define NM_TYPE_INTEGER64      122
#define NM_TYPE_UNSIGNED64     123

#define NM_TYPE_NSAPADDR NM_TYPE_NSAPADDRESS
#define NM_TYPE_DISPLAY NM_TYPE_INTEGER32

#define	NM_SNMP_NOSUCHOBJECT	128
#define	NM_SNMP_NOSUCHINSTANCE	129
#define	NM_SNMP_ENDOFMIBVIEW	130

#define nm_snmp_validtype(type)	(((type > NM_TYPE_OTHER) && (type <= NM_TYPE_DISPLAY)) || \
                                 ((type > NM_TYPE_APP_OPAQUE) && (type <= NM_TYPE_UNSIGNED64)) || \
                                  (type == NM_SNMP_NOSUCHOBJECT) || \
                                  (type == NM_SNMP_NOSUCHINSTANCE) || \
                                  (type == NM_SNMP_ENDOFMIBVIEW))

#endif
