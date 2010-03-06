/*
 * nm_snmp.h
 */

#ifndef nm_snmp_h
#define	nm_snmp_h

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/snmp_client.h>

#include "nm_snmpdefs.h"
#include "nm_util.h"
#include "nm_trap.h"

#define DEFAULT_TIMEOUT	1000000L

/* Tamanho pacote ( == cmu ) */
#define PACKET_LENGTH   4500

#define RECEIVED_MESSAGE NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE
#define TIMED_OUT NETSNMP_CALLBACK_OP_TIMED_OUT
/*
 * Estrutura de controle de um request assincrono
 */

typedef struct ReqList {
	struct ReqList *next;
	long   reqid;		/* Request id */
	int    reqcb;		/* Rotina (lua_ref) p/ callback do request */
	int    magic;		/* Param (lua_ref) p/ callback do request */
        int    is_list;		/* Flag para o tipo de vb retornado */
} ReqList;

/*
 * Estrutura de controle para sessao com close pendente
 */

typedef struct snmp_session CmuSession;

typedef struct CloseList {
	struct CloseList *next;
	CmuSession *cmu_session;
} CloseList;


/*
 * Estrutura para controle de uma sessao
 */

typedef struct synch_state CmuSynchState;

typedef struct Tsession {
  struct Tsession *next;
  int lua_session;		/* sessao para usr (ref a table lua) */
  int no_peer;			/* indica se peer definido */
#if 1
  u_long peer_addr;			/* endereco IP do peer */
#else
  char peer_addr[32];
#endif
  char peer_ip[32];
  netsnmp_session *cmu_session;	/* sessao CMU associada */
  int as_reqs;			/* num requests assincronos pendentes */
  ReqList *as_reqs_lst;		/* fila requests assincronos pendentes */
  int synch_req;			/* indica se tem req sincrono pendente */
  CmuSynchState cmu_synch_state;  /* estrutura controle req sincrono (cmu)*/
  int defcb;			/* flag and key for default callback */
  int trapcb;			/* flag and key for trap callback */
  int infocb;			/* flag and key for inform callback */
  int vbindmetatable;           /* flag and key for vbind metatable */
  lua_State *L;
  u_short trap_port;
} Tsession;

/*
 * Definicoes para uso de sockets (select)
 */

#ifndef FD_ZERO
#define FD_ZERO(p)      bzero((char *)(p), sizeof(*(p)))
#endif
 

#endif
