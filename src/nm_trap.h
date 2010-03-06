/*
 * nm_trap.h
 */

#ifndef nm_trap_h
#define	nm_trap_h

/*
 * Prototipos das funcoes definidas por nm_trap
 */
#ifdef USE_SNMPTRAPD
#define NM_SNMP_TRAP_PORT 6000
#define NM_SNMP_TRAP_BUFLEN 4096
void nm_trap_open(const char *name, int port);
void nm_trap_close(void);
int nm_trap_event(char *buf, int buflen);
#else
void nm_trap_open(char *straps, int port);
void nm_trap_close(void);
int nm_trap_event(u_char *packet, int *length, struct sockaddr_in *from);
#endif
#endif

