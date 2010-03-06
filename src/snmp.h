#ifndef _SNMP_H_
#define _SNMP_H_

#define snmp_mib_tree tree

/* LuaMan: added snmp_errno and Mib definitions */
extern int snmp_errno;
extern struct snmp_mib_tree *Mib;

#endif /* _SNMP_H_ */
