/*-----------------------------------------------------------------------------
 * nm_snmp.c
 *
 * This module implements the interface between Lua and the netsnmp library.
 * They provide the Lua interface to the 
 *----------------------------------------------------------------------------*/


#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/param.h>
#include <netdb.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "lua.h"
#include "lauxlib.h"

#include "nm_snmp.h"
#include "nm_mib.h"
#include "except.h"
#include "nm_c64.h"

#define MYNAME "snmp"
#define MYVERSION VERSION
#define MYSYSTEM SYSTEM

#define USM_OID_LEN    12
#define DH_USM_OID_LEN    11

/*-----------------------------------------------------------------------------
 * Local variables
 *----------------------------------------------------------------------------*/

/*
 * Path pointing to helper programs, e.g. straps 
 */
#ifndef USE_SNMPTRAPD
static char nm_snmp_straps[256];
static int nm_snmp_straps_port = SNMP_TRAP_PORT;
static int nm_snmp_init_done = 0;
#else
static int nm_snmp_trap_port = NM_SNMP_TRAP_PORT;
#endif
/*
 * Peer default (unspecified)
 */
static char peer_def[] = "0.0.0.0";

/*
 * PDU pointer for reception of synchronous responses
 */
struct snmp_pdu *synch_response;

/*
 * Pointer to the "mother" of all sessions
 */
static CmuSession nm_cmu_session;

/*
 * List of active sessions
 */
static Tsession *nm_snmp_sessions = NULL;

/*
 * Reference counters for pending requests
 */
static int nm_snmp_sync_reqs = 0;
static int nm_snmp_async_reqs = 0;

/*
 * Flag indicating whether a user callback is executed
 */
static int nm_in_usr_cback = 0;
static CloseList *nm_close_list = NULL;

/*
 * Trap reference count
 */
static int nm_snmp_ntraps = 0;
#ifndef USE_SNMPTRAPD
static u_char nm_snmp_trappkt[PACKET_LENGTH];
#endif

/*
 * A global ref for the active Lua State
 */
static lua_State *lua_ref;

/*
 * USM authentication and privacy stuff
 */
#ifdef REMOVE_THIS
static oid authKeyOid[MAX_OID_LEN]       = { 1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 6 },
  privKeyOid[MAX_OID_LEN]       = {1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 9};
#endif

#ifdef REMOVE_THIS
  ownAuthKeyOid[MAX_OID_LEN]    = {1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 7},
  ownPrivKeyOid[MAX_OID_LEN]    = {1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 10},
  usmUserCloneFrom[MAX_OID_LEN] = {1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 4},
  usmUserSecurityName[MAX_OID_LEN] = {1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 3},
  usmUserStatus[MAX_OID_LEN] = {1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 13},
  /* diffie helman change key objects */
  usmDHUserAuthKeyChange[MAX_OID_LEN] = {1, 3, 6, 1, 3, 101, 1, 1, 2, 1, 1 },
  usmDHUserOwnAuthKeyChange[MAX_OID_LEN] = {1, 3, 6, 1, 3, 101, 1, 1, 2, 1, 2 },
  usmDHUserPrivKeyChange[MAX_OID_LEN] = {1, 3, 6, 1, 3, 101, 1, 1, 2, 1, 3 },
  usmDHUserOwnPrivKeyChange[MAX_OID_LEN] = {1, 3, 6, 1, 3, 101, 1, 1, 2, 1, 4 },
  usmDHParameters[] = { 1,3,6,1,3,101,1,1,1,0 };
#endif			
#ifdef REMOVE_THIS
static oid *authKeyChange = authKeyOid, *privKeyChange = privKeyOid;
#endif
size_t usmUserEngineIDLen = 0;
u_char *usmUserEngineID = NULL;


/*-----------------------------------------------------------------------------
 * Defines
 *----------------------------------------------------------------------------*/
#define NM_SNMP_PRINT_VALUE 0
#define NM_SNMP_PRINT_VARIABLE 1

#define MAX_PACKET_LENGTH PACKET_LENGTH

/*-----------------------------------------------------------------------------
 * Functions copied from net-snmp library.
 *  - We need them in order to process traps.
 *----------------------------------------------------------------------------*/
#ifndef USE_SNMPTRAPD
static const char *secLevelName[] = {
    "BAD_SEC_LEVEL",
    "noAuthNoPriv",
    "authNoPriv",
    "authPriv"
};


/*
 * FROM NET-SNMP:
 * Parses the packet received to determine version, either directly
 * from packets version field or inferred from ASN.1 construct.
 */
static int
snmp_parse_version(u_char * data, size_t length)
{
    u_char          type;
    long            version = SNMPERR_BAD_VERSION;

    data = asn_parse_sequence(data, &length, &type,
                              (ASN_SEQUENCE | ASN_CONSTRUCTOR), "version");
    if (data) {
        data =
            asn_parse_int(data, &length, &type, &version, sizeof(version));
        if (!data || type != ASN_INTEGER) {
            return SNMPERR_BAD_VERSION;
        }
    }
    return version;
}
#define DEBUGPRINTPDUTYPE(token, type) printf("### %s %d\n", token, type)
/*
 * FROM NET-SNMP:
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.
 * If any errors are encountered, -1 or USM error is returned.
 * Otherwise, a 0 is returned.
 */
static int
_snmp_parse(void *sessp,
            netsnmp_session * session,
            netsnmp_pdu *pdu, u_char * data, size_t length)
{
    u_char          community[COMMUNITY_MAX_LEN];
    size_t          community_length = COMMUNITY_MAX_LEN;
    int             result = -1;

    session->s_snmp_errno = 0;
    session->s_errno = 0;

    /*
     * Ensure all incoming PDUs have a unique means of identification 
     * (This is not restricted to AgentX handling,
     * though that is where the need becomes visible)   
     */
    pdu->transid = snmp_get_next_transid();

    if (session->version != SNMP_DEFAULT_VERSION) {
        pdu->version = session->version;
    } else {
        pdu->version = snmp_parse_version(data, length);
    }

    switch (pdu->version) {
    case SNMP_VERSION_1:
    case SNMP_VERSION_2c:
        DEBUGMSGTL(("snmp_api", "Parsing SNMPv%ld message...\n",
                    (1 + pdu->version)));

        /*
         * authenticates message and returns length if valid 
         */
        if (pdu->version == SNMP_VERSION_1) {
            DEBUGDUMPSECTION("recv", "SNMPv1 message\n");
        } else {
            DEBUGDUMPSECTION("recv", "SNMPv2c message\n");
        }
        data = snmp_comstr_parse(data, &length,
                                 community, &community_length,
                                 &pdu->version);
        if (data == NULL)
            return -1;

        if (pdu->version != session->version &&
            session->version != SNMP_DEFAULT_VERSION) {
            session->s_snmp_errno = SNMPERR_BAD_VERSION;
            return -1;
        }

        /*
         * maybe get the community string. 
         */
        pdu->securityLevel = SNMP_SEC_LEVEL_NOAUTH;
        pdu->securityModel = (pdu->version == SNMP_VERSION_1) ?
            SNMP_SEC_MODEL_SNMPv1 : SNMP_SEC_MODEL_SNMPv2c;
        SNMP_FREE(pdu->community);
        pdu->community_len = 0;
        pdu->community = (u_char *) 0;
        if (community_length) {
            pdu->community_len = community_length;
            pdu->community = (u_char *) malloc(community_length);
            if (pdu->community == NULL) {
                session->s_snmp_errno = SNMPERR_MALLOC;
                return -1;
            }
            memmove(pdu->community, community, community_length);
        }
        if (session->authenticator) {
            data = session->authenticator(data, &length,
                                          community, community_length);
            if (data == NULL) {
                session->s_snmp_errno = SNMPERR_AUTHENTICATION_FAILURE;
                return -1;
            }
        }

        DEBUGDUMPSECTION("recv", "PDU");
        result = snmp_pdu_parse(pdu, data, &length);
        if (result < 0) {
            /*
             * This indicates a parse error.  
             */
            snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        }
        DEBUGINDENTADD(-6);
        break;

    case SNMP_VERSION_3:
        result = snmpv3_parse(pdu, data, &length, NULL, session);
        DEBUGMSGTL(("snmp_parse",
                    "Parsed SNMPv3 message (secName:%s, secLevel:%s): %s\n",
                    pdu->securityName, secLevelName[pdu->securityLevel],
                    snmp_api_errstring(result)));

        if (result) {
            if (!sessp) {
                session->s_snmp_errno = result;
            } else {

                /*
                 * handle reportable errors 
                 */
                switch (result) {
                case SNMPERR_USM_AUTHENTICATIONFAILURE:
		  {
                    int res = session->s_snmp_errno;
                    session->s_snmp_errno = result;
                    if (session->callback) {
                       session->callback(NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE,
                            session, pdu->reqid, pdu, session->callback_magic);
                    }
                    session->s_snmp_errno = res;
                  }  
                case SNMPERR_USM_UNKNOWNENGINEID:
                case SNMPERR_USM_UNKNOWNSECURITYNAME:
                case SNMPERR_USM_UNSUPPORTEDSECURITYLEVEL:
                case SNMPERR_USM_NOTINTIMEWINDOW:
                case SNMPERR_USM_DECRYPTIONERROR:

                    if (SNMP_CMD_CONFIRMED(pdu->command) ||
                        (pdu->command == 0
                         && (pdu->flags & SNMP_MSG_FLAG_RPRT_BIT))) {
                        netsnmp_pdu    *pdu2;
                        int             flags = pdu->flags;

                        pdu->flags |= UCD_MSG_FLAG_FORCE_PDU_COPY;
                        pdu2 = snmp_clone_pdu(pdu);
                        pdu->flags = pdu2->flags = flags;
                        snmpv3_make_report(pdu2, result);
                        if (0 == snmp_sess_send(sessp, pdu2)) {
                            snmp_free_pdu(pdu2);
                            /*
                             * TODO: indicate error 
                             */
                        }
                    }
                    break;
                default:
                    session->s_snmp_errno = result;
                    break;
                }
            }
        }
        break;
    case SNMPERR_BAD_VERSION:
        ERROR_MSG("error parsing snmp message version");
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        session->s_snmp_errno = SNMPERR_BAD_VERSION;
        break;
    case SNMP_VERSION_sec:
    case SNMP_VERSION_2u:
    case SNMP_VERSION_2star:
    case SNMP_VERSION_2p:
    default:
        ERROR_MSG("unsupported snmp message version");
        snmp_increment_statistic(STAT_SNMPINBADVERSIONS);

        /*
         * need better way to determine OS independent
         * INT32_MAX value, for now hardcode
         */
        if (pdu->version < 0 || pdu->version > 2147483647) {
            snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        }
        session->s_snmp_errno = SNMPERR_BAD_VERSION;
        break;
    }

    return result;
}

static int
snmp_parse(void *sessp,
           netsnmp_session * pss,
           netsnmp_pdu *pdu, u_char * data, size_t length)
{
    int             rc;

    rc = _snmp_parse(sessp, pss, pdu, data, length);
    if (rc) {
        if (!pss->s_snmp_errno) {
            pss->s_snmp_errno = SNMPERR_BAD_PARSE;
        }
        SET_SNMP_ERROR(pss->s_snmp_errno);
    }

    return rc;
}

int
snmp_pdu_parse(netsnmp_pdu *pdu, u_char * data, size_t * length)
{
    u_char          type;
    u_char          msg_type;
    u_char         *var_val;
    int             badtype = 0;
    size_t          len;
    size_t          four;
    netsnmp_variable_list *vp = NULL;
    oid             objid[MAX_OID_LEN];

    /*
     * Get the PDU type 
     */
    data = asn_parse_header(data, length, &msg_type);
    if (data == NULL)
        return -1;
    pdu->command = msg_type;
    pdu->flags &= (~UCD_MSG_FLAG_RESPONSE_PDU);

    /*
     * get the fields in the PDU preceeding the variable-bindings sequence 
     */
    switch (pdu->command) {
    case SNMP_MSG_TRAP:
        /*
         * enterprise 
         */
        pdu->enterprise_length = MAX_OID_LEN;
        data = asn_parse_objid(data, length, &type, objid,
                               &pdu->enterprise_length);
        if (data == NULL)
            return -1;
        pdu->enterprise =
            (oid *) malloc(pdu->enterprise_length * sizeof(oid));
        if (pdu->enterprise == NULL) {
            return -1;
        }
        memmove(pdu->enterprise, objid,
                pdu->enterprise_length * sizeof(oid));

        /*
         * agent-addr 
         */
        four = 4;
        data = asn_parse_string(data, length, &type,
                                (u_char *) pdu->agent_addr, &four);
        if (data == NULL)
            return -1;

        /*
         * generic trap 
         */
        data = asn_parse_int(data, length, &type, (long *) &pdu->trap_type,
                             sizeof(pdu->trap_type));
        if (data == NULL)
            return -1;
        /*
         * specific trap 
         */
        data =
            asn_parse_int(data, length, &type,
                          (long *) &pdu->specific_type,
                          sizeof(pdu->specific_type));
        if (data == NULL)
            return -1;

        /*
         * timestamp  
         */
        data = asn_parse_unsigned_int(data, length, &type, &pdu->time,
                                      sizeof(pdu->time));
        if (data == NULL)
            return -1;

        break;

    case SNMP_MSG_RESPONSE:
    case SNMP_MSG_REPORT:
        pdu->flags |= UCD_MSG_FLAG_RESPONSE_PDU;
        /*
         * fallthrough 
         */

    case SNMP_MSG_GET:
    case SNMP_MSG_GETNEXT:
    case SNMP_MSG_GETBULK:
    case SNMP_MSG_TRAP2:
    case SNMP_MSG_INFORM:
    case SNMP_MSG_SET:
        /*
         * PDU is not an SNMPv1 TRAP 
         */

        /*
         * request id 
         */
        DEBUGDUMPHEADER("recv", "request_id");
        data = asn_parse_int(data, length, &type, &pdu->reqid,
                             sizeof(pdu->reqid));
        DEBUGINDENTLESS();
        if (data == NULL) {
            return -1;
        }

        /*
         * error status (getbulk non-repeaters) 
         */
        DEBUGDUMPHEADER("recv", "error status");
        data = asn_parse_int(data, length, &type, &pdu->errstat,
                             sizeof(pdu->errstat));
        DEBUGINDENTLESS();
        if (data == NULL) {
            return -1;
        }

        /*
         * error index (getbulk max-repetitions) 
         */
        DEBUGDUMPHEADER("recv", "error index");
        data = asn_parse_int(data, length, &type, &pdu->errindex,
                             sizeof(pdu->errindex));
        DEBUGINDENTLESS();
        if (data == NULL) {
            return -1;
        }
	break;

    default:
        snmp_log(LOG_ERR, "Bad PDU type received: 0x%.2x\n", pdu->command);
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        return -1;
    }

    /*
     * get header for variable-bindings sequence 
     */
    DEBUGDUMPSECTION("recv", "VarBindList");
    data = asn_parse_sequence(data, length, &type,
                              (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                              "varbinds");
    if (data == NULL)
        return -1;

    /*
     * get each varBind sequence 
     */
    while ((int) *length > 0) {
        netsnmp_variable_list *vptemp;
        vptemp = (netsnmp_variable_list *) malloc(sizeof(*vptemp));
        if (0 == vptemp) {
            return -1;
        }
        if (0 == vp) {
            pdu->variables = vptemp;
        } else {
            vp->next_variable = vptemp;
        }
        vp = vptemp;

        vp->next_variable = NULL;
        vp->val.string = NULL;
        vp->name_length = MAX_OID_LEN;
        vp->name = 0;
        vp->index = 0;
        vp->data = 0;
        vp->dataFreeHook = 0;
        DEBUGDUMPSECTION("recv", "VarBind");
        data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type,
                                 &vp->val_len, &var_val, length);
        if (data == NULL)
            return -1;
        if (snmp_set_var_objid(vp, objid, vp->name_length))
            return -1;

        len = MAX_PACKET_LENGTH;
        DEBUGDUMPHEADER("recv", "Value");
        switch ((short) vp->type) {
        case ASN_INTEGER:
            vp->val.integer = (long *) vp->buf;
            vp->val_len = sizeof(long);
            asn_parse_int(var_val, &len, &vp->type,
                          (long *) vp->val.integer,
                          sizeof(*vp->val.integer));
            break;
        case ASN_COUNTER:
        case ASN_GAUGE:
        case ASN_TIMETICKS:
        case ASN_UINTEGER:
            vp->val.integer = (long *) vp->buf;
            vp->val_len = sizeof(u_long);
            asn_parse_unsigned_int(var_val, &len, &vp->type,
                                   (u_long *) vp->val.integer,
                                   vp->val_len);
            break;
#ifdef OPAQUE_SPECIAL_TYPES
        case ASN_OPAQUE_COUNTER64:
        case ASN_OPAQUE_U64:
#endif                          /* OPAQUE_SPECIAL_TYPES */
        case ASN_COUNTER64:
            vp->val.counter64 = (struct counter64 *) vp->buf;
            vp->val_len = sizeof(struct counter64);
            asn_parse_unsigned_int64(var_val, &len, &vp->type,
                                     (struct counter64 *) vp->val.
                                     counter64, vp->val_len);
            break;
#ifdef OPAQUE_SPECIAL_TYPES
        case ASN_OPAQUE_FLOAT:
            vp->val.floatVal = (float *) vp->buf;
            vp->val_len = sizeof(float);
            asn_parse_float(var_val, &len, &vp->type,
                            vp->val.floatVal, vp->val_len);
            break;
        case ASN_OPAQUE_DOUBLE:
            vp->val.doubleVal = (double *) vp->buf;
            vp->val_len = sizeof(double);
            asn_parse_double(var_val, &len, &vp->type,
                             vp->val.doubleVal, vp->val_len);
            break;
        case ASN_OPAQUE_I64:
            vp->val.counter64 = (struct counter64 *) vp->buf;
            vp->val_len = sizeof(struct counter64);
            asn_parse_signed_int64(var_val, &len, &vp->type,
                                   (struct counter64 *) vp->val.counter64,
                                   sizeof(*vp->val.counter64));

            break;
#endif                          /* OPAQUE_SPECIAL_TYPES */
        case ASN_OCTET_STR:
        case ASN_IPADDRESS:
        case ASN_OPAQUE:
        case ASN_NSAP:
            if (vp->val_len < sizeof(vp->buf)) {
                vp->val.string = (u_char *) vp->buf;
            } else {
                vp->val.string = (u_char *) malloc(vp->val_len);
            }
            if (vp->val.string == NULL) {
                return -1;
            }
            asn_parse_string(var_val, &len, &vp->type, vp->val.string,
                             &vp->val_len);
            break;
        case ASN_OBJECT_ID:
            vp->val_len = MAX_OID_LEN;
            asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
            vp->val_len *= sizeof(oid);
            vp->val.objid = (oid *) malloc(vp->val_len);
            if (vp->val.objid == NULL) {
                return -1;
            }
            memmove(vp->val.objid, objid, vp->val_len);
            break;
        case SNMP_NOSUCHOBJECT:
        case SNMP_NOSUCHINSTANCE:
        case SNMP_ENDOFMIBVIEW:
        case ASN_NULL:
            break;
        case ASN_BIT_STR:
            vp->val.bitstring = (u_char *) malloc(vp->val_len);
            if (vp->val.bitstring == NULL) {
                return -1;
            }
            asn_parse_bitstring(var_val, &len, &vp->type,
                                vp->val.bitstring, &vp->val_len);
            break;
        default:
            snmp_log(LOG_ERR, "bad type returned (%x)\n", vp->type);
            badtype = -1;
            break;
        }
        DEBUGINDENTADD(-4);
    }
    return badtype;
}
void
snmp_free_var(netsnmp_variable_list * var)
{
    if (!var)
        return;

    if (var->name != var->name_loc)
        SNMP_FREE(var->name);
    if (var->val.string != var->buf)
        SNMP_FREE(var->val.string);
    if (var->data) {
        if (var->dataFreeHook) {
            var->dataFreeHook(var->data);
            var->data = NULL;
        } else {
            SNMP_FREE(var->data);
        }
    }

    free((char *) var);
}
#endif /* USE_SNMPTRAPD */

/*-----------------------------------------------------------------------------
 * Function prototypes
 *----------------------------------------------------------------------------*/

static int nm_snmp_getreq(lua_State *L, int req_type, int req_mode);
static int nm_snmp_set_info_req(lua_State *L, int req_type,int req_mode);

static int nm_snmp_synch_req(lua_State *L, Tsession *nm_session, struct snmp_pdu *pdu, int islist);
static int nm_snmp_asynch_req(lua_State *L, Tsession *nm_session, struct snmp_pdu *pdu, int islist, int ref_cb, int ref_magic);
static int nm_snmp_callback(int op, CmuSession *session, int reqid, struct snmp_pdu *pdu, void *magic);
static void nm_snmp_freereqs(Tsession *nm_session);
static int nm_snmp_event(lua_State *L);
#ifdef USE_SNMPTRAPD
static void nm_snmp_trap(lua_State *L, char *buf, int rxlen);
#else
static void nm_snmp_trap(lua_State *L, u_char *packet, int length, struct sockaddr_in *from);
#endif
static Tsession *nm_snmp_getsession(lua_State *L);

/*-----------------------------------------------------------------------------
 * Function wrapped to Lua
 *----------------------------------------------------------------------------*/

static int nm_snmp_gettrapd(lua_State *L)
{
#ifdef USE_SNMPTRAPD
  lua_pushstring(L, "snmptrapd");
#else
  lua_pushstring(L, "straps");
#endif
  return 1;
}

static void nm_snmp_init_session(netsnmp_session *session)
{
  memset(session, 0, sizeof(netsnmp_session));
  session->remote_port = SNMP_DEFAULT_REMPORT;
  session->timeout = SNMP_DEFAULT_TIMEOUT;
  session->retries = SNMP_DEFAULT_RETRIES;
  session->version = SNMP_DEFAULT_VERSION;
  session->securityModel = SNMP_DEFAULT_SECMODEL;
  session->rcvMsgMaxSize = SNMP_MAX_MSG_SIZE;
  session->flags |= SNMP_FLAGS_DONT_PROBE;
}

/*-----------------------------------------------------------------------------
 *  nm_snmp_open
 *
 *  Synopsis : snmp.open(INIT_TABLE)
 *  Lua Param: INIT TABLE
 *  Return   : nil+error on failure, userdata + peer IP address to session on success
 *  Function : Opens an snmp session
 *----------------------------------------------------------------------------*/
static int nm_snmp_open(lua_State *L) {
  Tsession *nm_session;
  int version;
  int flg_nopeer;
  char *peername;
  struct in_addr peer_addr;
  char *Apsz, *Xpsz;

  /* Get a table from Lua stack */
  if (!lua_istable(L, -1)) {
    lua_pushnil(L);
    lua_pushstring(L, "snmp: internal failure");
    return 2;
  }

  /* Base parameters for the session */
#ifdef REMOVE_THIS
  memset((char *)&nm_cmu_session,0,sizeof(CmuSession));
#endif
  nm_snmp_init_session(&nm_cmu_session);
  lua_pushstring(L, "version");
  lua_gettable(L, -2);
  version = lua_tonumber(L, -1);
  lua_remove(L, -1);
  nm_cmu_session.version = version;

  if ((version == SNMP_VERSION_2c) || (version == SNMP_VERSION_1)){
    lua_pushstring(L, "community");
    lua_gettable(L, -2);
    nm_cmu_session.community = (u_char *) lua_tostring(L, -1);
    nm_cmu_session.community_len = strlen((char *)nm_cmu_session.community);
    lua_remove(L, -1);
  }

  /* Version 3 authentication stuff */
  if (version == SNMP_VERSION_3){

    lua_pushstring(L, "user");
    lua_gettable(L, -2);
    if (!lua_isnil(L, -1)){
      nm_cmu_session.securityName = (char *) lua_tostring(L, -1);
      nm_cmu_session.securityNameLen = strlen(lua_tostring(L, -1));
    }
    lua_remove(L,-1);

    lua_pushstring(L, "_securityLevel");
    lua_gettable(L, -2);
    if (!lua_isnil(L, -1))
      nm_cmu_session.securityLevel = (int) lua_tonumber(L, -1);
    lua_remove(L, -1);
    
    nm_cmu_session.securityModel = SNMP_DEFAULT_SECMODEL;

    /*
     *  Authentication Protocol
     */
    lua_pushstring(L, "authType");
    lua_gettable(L, -2);
    if (!lua_isnil(L, -1)){
      if (!strcmp(lua_tostring(L, -1), "MD5")){
	nm_cmu_session.securityAuthProto = usmHMACMD5AuthProtocol;
	nm_cmu_session.securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
      } else if (!strcmp(lua_tostring(L, -1), "SHA")){
	nm_cmu_session.securityAuthProto = usmHMACSHA1AuthProtocol;
	nm_cmu_session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
      } else if (!strcmp(lua_tostring(L, -1), "NOAUTH")){
	nm_cmu_session.securityAuthProto = usmHMACSHA1AuthProtocol;
	nm_cmu_session.securityAuthProtoLen = USM_AUTH_PROTO_NOAUTH_LEN;
      }
    }
    lua_remove(L, -1);
    
    /*
     *  Encryption Protocol
     */
    lua_pushstring(L, "privType");
    lua_gettable(L, -2);
    if (!lua_isnil(L, -1)){
      if (!strcmp(lua_tostring(L, -1), "DES")){
	nm_cmu_session.securityPrivProto = usmDESPrivProtocol;
	nm_cmu_session.securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
      } else if (!strcmp(lua_tostring(L, -1), "AES")){
	nm_cmu_session.securityPrivProto = usmAESPrivProtocol;
	nm_cmu_session.securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
      } else if (!strcmp(lua_tostring(L, -1), "NOAUTH")){
	nm_cmu_session.securityPrivProto = usmNoPrivProtocol;
	nm_cmu_session.securityPrivProtoLen = USM_PRIV_PROTO_NOPRIV_LEN;
      }
    }
    lua_remove(L, -1);
    
    lua_pushstring(L, "authPassphrase");
    lua_gettable(L, -2);
    Apsz = (char *) lua_tostring(L, -1);
    if (Apsz) {
      nm_cmu_session.securityAuthKeyLen = USM_AUTH_KU_LEN;
      if (generate_Ku(nm_cmu_session.securityAuthProto,
		      nm_cmu_session.securityAuthProtoLen,
		      (u_char *) Apsz, strlen(Apsz),
		      nm_cmu_session.securityAuthKey,
		      &nm_cmu_session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
	lua_remove(L, -1);
	lua_pushnil(L);
	lua_pushstring(L, "snmp: error generating key from authentication password.");
	return 2;
      }
    }
    lua_remove(L, -1);

    /*
     * Encryption password
     */
    lua_pushstring(L, "privPassphrase");
    lua_gettable(L, -2);
    Xpsz = (char *) lua_tostring(L, -1);
    if (Xpsz) {
      nm_cmu_session.securityPrivKeyLen = USM_PRIV_KU_LEN;
      if (generate_Ku(nm_cmu_session.securityAuthProto,
		      nm_cmu_session.securityAuthProtoLen,
		      (u_char *) Xpsz, strlen(Xpsz),
		      nm_cmu_session.securityPrivKey,
		      &nm_cmu_session.securityPrivKeyLen) != SNMPERR_SUCCESS) {
	lua_remove(L, -1);
	lua_pushnil(L);
	lua_pushstring(L, "snmp: error generating key from privacy password.");
	return 2;
      }
    }
    lua_remove(L, -1);
    
    lua_pushstring(L, "context");
    lua_gettable(L, -2);
    if (!lua_isnil(L, -1)){
      nm_cmu_session.contextName = (char *) lua_tostring(L, -1);
      nm_cmu_session.contextNameLen =  strlen(lua_tostring(L, -1));
    }
    lua_remove(L, -1);
    
    lua_pushstring(L, "engineID");
    lua_gettable(L, -2);
    if (!lua_isnil(L, -1)) {
      size_t ebuf_len = 32;
      size_t eout_len = 0;
      u_char *ebuf = (u_char *)malloc(ebuf_len);
      if (ebuf == NULL) {
	lua_remove(L, -1);
	lua_pushnil(L);
	lua_pushstring(L, "snmp: intenal memory error.");
	return 2;
      }
      if (!snmp_hex_to_binary(&ebuf, &ebuf_len, &eout_len, 1, lua_tostring(L, -1))){
	free(ebuf);
	lua_remove(L, -1);
	lua_pushnil(L);
	lua_pushstring(L, "snmp: bad authentication engine id");
	return 2;
      }
      nm_cmu_session.securityEngineID = ebuf;
      nm_cmu_session.securityEngineIDLen = eout_len;
    }
    lua_remove(L, -1);

    lua_pushstring(L, "contextId");
    lua_gettable(L, -2);
    if (!lua_isnil(L, -1)) {
      size_t ebuf_len = 32, eout_len = 0;
      u_char *ebuf = (u_char *)malloc(ebuf_len);
      if (ebuf == NULL) {
	lua_remove(L, -1);
	lua_pushnil(L);
	lua_pushstring(L, "snmp: intenal memory error.");
	return 2;
      }
      if (!snmp_hex_to_binary(&ebuf, &ebuf_len, &eout_len, 1, lua_tostring(L, -1))){
	free(ebuf);
	lua_remove(L, -1);
	lua_pushnil(L);
	lua_pushstring(L, "snmp: bad authentication engine id");
	return 2;
      }
      nm_cmu_session.contextEngineID = ebuf;
      nm_cmu_session.contextEngineIDLen = eout_len;
    }
    lua_remove(L, -1);
#ifdef  HERE    
    lua_pushstring(L, "boots");
#endif
  } /* Version 3 stuff */

  lua_pushstring(L, "timeout");
  lua_gettable(L, -2);
  nm_cmu_session.timeout = lua_tonumber(L, -1);
  lua_remove(L, -1);

  /* timeout in microseconds */
  nm_cmu_session.timeout *= DEFAULT_TIMEOUT;

  lua_pushstring(L, "retries");
  lua_gettable(L, -2);
  nm_cmu_session.retries = lua_tonumber(L, -1);
  lua_remove(L, -1);

  lua_pushstring(L, "peer");
  lua_gettable(L, -2);
  peername = (char *) lua_tostring(L, -1);
  nm_cmu_session.peername = peername;
  lua_remove(L, -1);

  /* Check whether we have a peer address (!= 0.0.0.0) */
  if (!strcmp(nm_cmu_session.peername, peer_def)) {
    flg_nopeer = TRUE;
    peer_addr.s_addr = 0;
  } else {
    flg_nopeer = FALSE;
    if (inet_aton((const char *) peername, &peer_addr) == 0){
      /* invalid dot notation - try to resolve dns */
      struct hostent *hp;
      if ((hp = gethostbyname(peername)) == NULL) {
        lua_pushnil(L);
        lua_pushstring(L, "snmp: bad peer address");
        return 2;
      }
      memcpy((char *)&peer_addr.s_addr, hp->h_addr, hp->h_length);
    }
  }

  lua_pushstring(L, "port");
  lua_gettable(L, -2);
  nm_cmu_session.remote_port = lua_tonumber(L, -1);
  lua_remove(L, -1);

  lua_pushstring(L, "localport");
  lua_gettable(L, -2);
  nm_cmu_session.local_port = lua_tonumber(L, -1);
  lua_remove(L, -1);

  /* Completa os outros campos da sessao CMU */
  nm_cmu_session.authenticator = NULL;

  /* Allocate Luasnmp session */
  nm_session=(Tsession *)malloc(sizeof(Tsession));
  if (nm_session == NULL) {
    lua_pushnil(L);
    lua_pushstring(L,"snmp: internal error - session allocation");
    return 2;
  }

  memset((char *)nm_session,0,sizeof(Tsession));

#if 0  
  lua_pushstring(L, "trapport");
  lua_gettable(L, -2);
  nm_session->trap_port = lua_tonumber(L, -1);
  lua_remove(L, -1);
#endif

  lua_pushstring(L, "callback");
  lua_gettable(L, -2);
  if (!lua_isnil(L, -1)) {
    lua_pushlightuserdata(L, &nm_session->defcb);
    lua_pushvalue(L, -2);
    lua_settable(L, LUA_REGISTRYINDEX);
    nm_session->defcb = 1;
  } else {
    nm_session->defcb = -1;
  }
  lua_remove(L, -1);

  lua_pushstring(L, "trap");
  lua_gettable(L, -2);
  if ((!lua_isnil(L, -1)) && (lua_isfunction(L, -1))) {
    lua_pushlightuserdata(L, &nm_session->trapcb);
    lua_pushvalue(L, -2);
    lua_settable(L, LUA_REGISTRYINDEX);
    nm_session->trapcb = 1;
  } else 
    nm_session->trapcb = -1;
  lua_remove(L, -1);

  lua_pushstring(L, "inform");
  lua_gettable(L, -2);
  if (!lua_isnil(L, -1)) {
    lua_pushlightuserdata(L, &nm_session->infocb);
    lua_pushvalue(L, -2);
    lua_settable(L, LUA_REGISTRYINDEX);
    nm_session->infocb = 1;
  } else
    nm_session->infocb = -1;
  lua_remove(L, -1);

#ifdef REMOVE_THIS
  /* vbindmetatable for varbindings */
  lua_pushstring(L, "vbindmetatable");
  lua_gettable(L, -2);
  if (!lua_isnil(L, -1)) {
    lua_pushlightuserdata(L, &vbindmetatable);
    lua_pushvalue(L, -2);
    lua_settable(L, LUA_REGISTRYINDEX);
    vbindmetatable = 1;
  } else
    vbindmetatable = -1;
  lua_remove(L, -1);
#endif

  /* Default request callback */
  nm_cmu_session.callback = nm_snmp_callback;
  nm_session->L = L;
  nm_cmu_session.callback_magic = (void *)nm_session;

  netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DEFAULT_PORT, 
  		     nm_cmu_session.remote_port);
  nm_session->cmu_session = snmp_open(&nm_cmu_session);
  if (nm_cmu_session.securityEngineID)
    free(nm_cmu_session.securityEngineID);
  if (nm_cmu_session.contextEngineID)
    free(nm_cmu_session.contextEngineID);
  if (nm_session->cmu_session == NULL) {
    char errs[256];
    free((char *)nm_session);
    lua_pushnil(L);
    sprintf(errs, "netsnmp: %s", snmp_api_errstring(snmp_errno));
    lua_pushstring(L, errs);
    return 2;
  }

  /* Session becomes active */
  nm_session->next = nm_snmp_sessions;

  /* Keep a reference to the Lua session in the registry */
  lua_pushlightuserdata(L, &nm_session->lua_session);
  lua_pushvalue(L, -2);
  lua_settable(L, LUA_REGISTRYINDEX);
  nm_session->no_peer = flg_nopeer;
  nm_session->peer_addr.s_addr = peer_addr.s_addr;
  sprintf(nm_session->peer_ip, "%d.%d.%d.%d", 
	  (int) ((htonl(peer_addr.s_addr) >> 24) & 0xFF), 
	  (int) ((htonl(peer_addr.s_addr) >> 16) & 0xFF),
	  (int) ((htonl(peer_addr.s_addr) >> 8) & 0xFF), 
	  (int) (htonl(peer_addr.s_addr) & 0xFF));
  nm_session->synch_req = FALSE;
  nm_session->as_reqs = 0;
  nm_session->as_reqs_lst = NULL;
  nm_snmp_sessions = nm_session;

  /* Prepare to receive traps via the AF_UNIX trap socket */
#ifndef USE_SNMPTRAPD
  if (nm_snmp_init_done > 0){
#endif
    if ((nm_session->trapcb != -1) || (nm_session->infocb != -1)) {
      if (nm_snmp_ntraps == 0){
#ifdef USE_SNMPTRAPD
	nm_trap_open(NULL, nm_snmp_trap_port);
#else
	nm_trap_open(nm_snmp_straps, nm_snmp_straps_port);
#endif
      }
      nm_snmp_ntraps++;
    }
#ifndef USE_SNMPTRAPD
  }
#endif
  lua_pushlightuserdata(L, (void *)nm_session);
  lua_pushstring(L, nm_session->peer_ip);
  return 2;
}

/*-----------------------------------------------------------------------------
 *  nm_snmp_close
 *
 *  Synopsis : snmp.close()
 *  Lua Param: sesssion
 *  Return   : nil on success, error msg on failure
 *  Function : closes a session
 *----------------------------------------------------------------------------*/
static int nm_snmp_close(lua_State *L) {
  Tsession *nm_session, *nxt_session, *prv_session;
  CmuSession *cmu_session;

#if 0
  if (nm_cmu_session.securityEngineID)
    free(nm_cmu_session.securityEngineID);
  if (nm_cmu_session.contextEngineID)
    free(nm_cmu_session.contextEngineID);
#endif

  if (!lua_istable(L, 1)) {
    lua_pushnil(L);
    lua_pushstring(L, "snmp: bad session");
    return 2;
  }
  lua_pushstring(L, "internal");
  lua_gettable(L, -2);
  if (!lua_isuserdata(L,-1)) {
    lua_pushnil(L);
    lua_pushstring(L, "snmp: bad session");
    return 2;
  }
  nm_session = lua_touserdata(L, -1);

  /* Dequeue this session from list of sessions */
  if (nm_snmp_sessions != NULL) {
    if (nm_snmp_sessions == nm_session)
      nm_snmp_sessions = nm_session->next;
    else {
      for (prv_session = nm_snmp_sessions, nxt_session = nm_snmp_sessions->next;
           nxt_session;
           nxt_session = nxt_session->next) {
        if ( nxt_session == nm_session ) {
          prv_session->next = nm_session->next;
          break;
        }
        prv_session = nxt_session;
      }
      if (nxt_session == NULL) {
	lua_pushnil(L);
	lua_pushstring(L, "snmp: bad session");
        return 2;
      }
    }
  } else {
    lua_pushnil(L);
    lua_pushstring(L, "snmp: bad session");
    return 2;
  }

  cmu_session = nm_session->cmu_session;

  /* Free asynch requests from internal sessions */
  nm_snmp_freereqs(nm_session);

  /* Unref default callback */
  lua_pushlightuserdata(L, &nm_session->defcb);
  lua_pushnil(L);
  lua_settable(L, LUA_REGISTRYINDEX);

  /* Cleanup trap and inform callback registrations */
  if ((nm_session->trapcb != -1) || (nm_session->infocb != -1)) {
    nm_snmp_ntraps--;
    if (nm_snmp_ntraps == 0)
      nm_trap_close();
    if (nm_session->trapcb != -1) {
      lua_pushlightuserdata(L, &nm_session->trapcb);
      lua_pushnil(L);
      lua_settable(L, LUA_REGISTRYINDEX);
    }
    if (nm_session->infocb != -1) {
      lua_pushlightuserdata(L, &nm_session->trapcb);
      lua_pushnil(L);
      lua_settable(L, LUA_REGISTRYINDEX);
    }
  }
  /* Unref vbmetatable */
#ifdef REMOVE_THIS
  lua_pushlightuserdata(L, &vbindmetatable);
  lua_pushnil(L);
  lua_settable(L, LUA_REGISTRYINDEX);
#endif

  /* Free reference to Lua session in registry and let Lua collect it */
  lua_pushlightuserdata(L, &nm_session->lua_session);
  lua_pushnil(L);
  lua_settable(L, LUA_REGISTRYINDEX);

  /* Build a list of sessions that are in a callback in order to close them
     eventually */
  if (nm_in_usr_cback) {
    CloseList *pclose = (CloseList *)malloc(sizeof(CloseList));
    if (pclose != NULL) {
      pclose->cmu_session = cmu_session;
      pclose->next = nm_close_list;
      nm_close_list = pclose;
    }
    lua_pushstring(L, "internal");
    lua_pushnil(L);
    lua_settable(L, 1);
    lua_pushnumber(L, 1);
    return 1;
  } else {
    free(nm_session);
    if (snmp_close(cmu_session)){ 
      lua_pushstring(L, "internal");
      lua_pushnil(L);
      lua_settable(L, 1);
      lua_pushnumber(L, 1);
      return 1;
    } else {
      lua_pushnil(L);
      lua_pushstring(L, "snmp: bad session");
      return 2;
    }
  }
}
/*-----------------------------------------------------------------------------
 * nm_snmp_get
 * nm_snmp_getnext
 * nm_snmp_asynch_get
 * nm_snmp_asynch_getnext
 *
 *  Synopsis : snmp.get(session, vars); vars is a string or table
 *  Lua Param: session, var (string) or var (list of strings)
 *  Return   : vbind or vbind list on success, 
 *             nil + error msg on failure
 *             vbind + status + errindex on response PDU error
 *  Function : Get an snmp object given by name or OID.
 *  Example:   vb, err, ix = sess:get(vlist) 
 *----------------------------------------------------------------------------*/
static int  nm_snmp_get(lua_State *L) {
  return nm_snmp_getreq(L, NM_SNMP_GET_REQ,NM_SNMP_SYNCH_REQ);
}
static int nm_snmp_getnext(lua_State *L) {
  return nm_snmp_getreq(L, NM_SNMP_GETNEXT_REQ,NM_SNMP_SYNCH_REQ);
}
static int  nm_snmp_asynch_get(lua_State *L) {
  return nm_snmp_getreq(L, NM_SNMP_GET_REQ,NM_SNMP_ASYNCH_REQ);
}
static int nm_snmp_asynch_getnext(lua_State *L) {
  return nm_snmp_getreq(L, NM_SNMP_GETNEXT_REQ,NM_SNMP_ASYNCH_REQ);
}

/*-----------------------------------------------------------------------------
 *  nm_snmp_getbulk
 *  nm_snmp_asynch_getbulk
 *
 *  Synopsis : snmp.getbulk(session, nr, mr, vars)
 *             snmp.asynch_getbulk(session, nr, mr, vars [, callback])
 *  Lua Param: see above.
 *  Return   : vbind list on success,
 *             error msg on failure
 *             vbind list + status + errindex on response PDU error
 *  Function : Get a bulk of variables
 *  Example  : vl, err, ix = sess:getbulk(0,3,vars)
 *----------------------------------------------------------------------------*/
static int nm_snmp_getbulk(lua_State *L) {
  return nm_snmp_getreq(L, NM_SNMP_BULK_REQ,NM_SNMP_SYNCH_REQ);
}
static int nm_snmp_asynch_getbulk(lua_State *L) {
  return nm_snmp_getreq(L, NM_SNMP_BULK_REQ,NM_SNMP_ASYNCH_REQ);
}

/*-----------------------------------------------------------------------------
 *  nm_snmp_getreq
 *
 *  Synopsis : see above
 *  Lua Param: see above
 *  Return   : see above
 *  Function : Handles all get, get next and get bulk requests.
 *----------------------------------------------------------------------------*/
static int nm_snmp_getreq(lua_State *L, int req_type, int req_mode) {
  Tsession *nm_session;
  int vlist;
  int usr_callb, usr_magic;
  int islist = -1, ind;
  struct snmp_pdu *pdu;
  oid objid[NMAX_SUBID];
  int objidlen;
  int ref_cb = -1;
  int ref_magic = -1;
  int lnr = 0;
  int lmr = 0;
  int narg;
  int retval;

  if (req_type == NM_SNMP_BULK_REQ) {
    lnr = 2;
    lmr = 3;
    vlist = 4;
    usr_callb = 5;
    usr_magic = 6;
  } else {
    vlist = 2;
    usr_callb = 3;
    usr_magic = 4;
  }

  narg = lua_gettop(L);

  if (req_mode == NM_SNMP_ASYNCH_REQ) {
    /* Check parameter magic */
    if ((narg > 3) && (!lua_isnil(L, usr_magic)))
      ref_magic=usr_magic;
    else
      ref_magic = -1;
  
    /* Check parameter callback */
    if ((narg > 2) && (!lua_isnil(L, usr_callb))) {
      if (!lua_isfunction(L, usr_callb)) {
	lua_pushnil(L);
	lua_pushstring(L, "snmp: bad callback");
	return 2;
      }
      ref_cb=usr_callb;
    } else {
      ref_cb = -1;
    }
  }
    
  /* Get the internal session from external session */
  lua_pushvalue(L, 1);
  nm_session = nm_snmp_getsession(L);
  if (nm_session == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "snmp: bad session");
    return 2;
  }

  /* We need a peer for get requests */
  if (nm_session->no_peer) {
    lua_pushnil(L);
    lua_pushstring(L, "snmp: bad peer");
    return 2;
  }

  /* Asynch request, check for default callback function */
  if (req_mode == NM_SNMP_ASYNCH_REQ) {
    if ((ref_cb == -1) && (nm_session->defcb == -1)) {
      lua_pushnil(L);
      lua_pushstring(L, "snmp: bad callback");
      return 2;
    }
  }

  /* Bulk request - check parameter nr and mr */
  if (req_type == NM_SNMP_BULK_REQ) {
    if (!lua_isnumber(L, lnr)) {
      lua_pushnil(L);
      lua_pushstring(L, "snmp: invalid argument (non-repeaters)");
      return 2;
    }
    if (!lua_isnumber(L, lmr)) {
      lua_pushnil(L);
      lua_pushstring(L, "snmp: invalid argument (max-repetitions)");
      return 2;
    }

    /* Se a sessao e' SNMPv1 faz um getnext em vez de getbulk */
    if (nm_session->cmu_session->version == SNMP_VERSION_1)
      pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
    else {
      pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
      pdu->non_repeaters  = (int) lua_tonumber(L, lnr);
      pdu->max_repetitions  = (int) lua_tonumber(L, lmr);
    }
  } else {
    /* Prepara o pdu para o request */
    if (req_type == NM_SNMP_GET_REQ)
      pdu = snmp_pdu_create(SNMP_MSG_GET) ;
    else
      pdu = snmp_pdu_create(SNMP_MSG_GETNEXT) ;
  }
  if (!lua_isnil(L, vlist)){
    /* Check how the objects to retrieve are described */
    if (!lua_istable(L, vlist)) {
      /* Not a table => not a list */
      islist = FALSE;
      lua_pushvalue(L, vlist);
    } else {
      lua_pushstring(L, "oid");
      lua_gettable(L, vlist);
      if (!lua_isnil(L, -1))
	/* OID value given => not a list */
	islist = FALSE;
      else {
	/* No OID value given => list */
	islist = TRUE;
	lua_remove(L, -1);
      }
    }
    
    if (!islist) {
      /* Single variable */
      if (f_var2mibnode(L, objid,&objidlen) == NULL) {
	lua_remove(L, -1);
	lua_pushnil(L);
	lua_pushstring(L, "snmp: bad name");
	snmp_free_pdu(pdu);
	return 2;
      }
      lua_remove(L, -1);
      snmp_add_null_var(pdu,objid,objidlen);
    } else {
      /* List of variables */
      for (ind = 1; ; ind++) {
	lua_rawgeti(L, vlist, ind);
	if (lua_isnil(L, -1)){
	  lua_remove(L, -1);
	  break;
	}
	if (f_var2mibnode(L, objid,&objidlen) == NULL) {
	  char errs[32];
	  lua_remove(L, -1);
	  lua_pushnil(L);
	  sprintf(errs, "snmp: bad name in index %d", ind);
	  lua_pushstring(L, errs);
	  snmp_free_pdu(pdu);
	  return 2;
	}
	lua_remove(L, -1);
	snmp_add_null_var(pdu,objid,objidlen);
      }
    }
  }
  /* Either synch or asynch request */
  if (req_mode == NM_SNMP_SYNCH_REQ)
    retval = nm_snmp_synch_req(L, nm_session, pdu, islist);
  else
    retval = nm_snmp_asynch_req(L, nm_session, pdu, islist, ref_cb, ref_magic);

  return retval;
}

/*-----------------------------------------------------------------------------
 *  nm_snmp_set
 *  nm_snmp_asynch_set
 *
 *  Synopsis : snmp.set(session, vars)
 *  Lua Param: session, single var or a list of vars
 *  Return   : vbind or vlist on success, 
 *             nil + error msg on failure.
 *             vbind or vlist + status + errindex on response PDU error
 *  Function : Sets one or more objects.
 *----------------------------------------------------------------------------*/
static int nm_snmp_set(lua_State *L) {
  return nm_snmp_set_info_req(L, NM_SNMP_SET_REQ,NM_SNMP_SYNCH_REQ);
}
static int nm_snmp_asynch_set(lua_State *L) {
  return nm_snmp_set_info_req(L, NM_SNMP_SET_REQ,NM_SNMP_ASYNCH_REQ);
}

/*-----------------------------------------------------------------------------
 *  nm_snmp_info
 *  nm_snmp_asynch_info
 *
 *  Synopsis : snmp.inform(sess, trapoid, vars)
 *  Lua Param: session, an OID describing the trap and a single var/list of vars
 *  Return   : vbind or vlist on success, 
 *             nil + error msg on failure
 *             vbind or vlist + status + errindex on response PDU error
 *  Function : Sends an inform request.
 *----------------------------------------------------------------------------*/
static int nm_snmp_inform(lua_State *L) {
  int retval;
  retval = nm_snmp_set_info_req(L, NM_SNMP_INFO_REQ,NM_SNMP_SYNCH_REQ);
  return retval;
}
static int nm_snmp_asynch_inform(lua_State *L) {
  return nm_snmp_set_info_req(L, NM_SNMP_INFO_REQ,NM_SNMP_ASYNCH_REQ);
}

/*-----------------------------------------------------------------------------
 *  nm_snmp_set_info_req
 *
 *  Synopsis : see above.
 *  Lua Param: see above, depends on request.
 *  Return   : see above, depends on request
 *  Function : Process any request.
 *----------------------------------------------------------------------------*/
static int nm_snmp_set_info_req(lua_State *L, int req_type, int req_mode) {
  Tsession *nm_session;
  int vlist;
  int usr_callb, usr_magic, trapOID = 0;
  int islist, ind;
  struct snmp_pdu *pdu;
  char errs[128];
  struct variable_list *varlist;
  struct variable_list *last_var = NULL;
  int ref_cb = -1;
  int ref_magic = -1;
  int narg;
  int retval;

  if (req_type == NM_SNMP_SET_REQ) {
    vlist = 2;
    usr_callb = 3;
    usr_magic = 4;
  } else {
    trapOID = 2;
    vlist = 3;
    usr_callb = 4;
    usr_magic = 5;
  }

  narg = lua_gettop(L);

  if (req_mode == NM_SNMP_ASYNCH_REQ) {
    /* Check parameter magic */
    if ((narg > 4) && (!lua_isnil(L, usr_magic)))
      ref_magic=usr_magic;
    else
      ref_magic = -1;
    
    /* Check parameter callback */
    if ((narg > 3) && (!lua_isnil(L, usr_callb))) {
      if (!lua_isfunction(L, usr_callb)) {
	lua_pushnil(L);
	lua_pushstring(L, "snmp: bad callback");
	return 2;
      }
      ref_cb=usr_callb;
    } else {
      ref_cb = -1;
    }
  }

  /* Session handle */
  lua_pushvalue(L, 1);
  nm_session = nm_snmp_getsession(L);
  if (nm_session == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "snmp: bad session");
    return 3;
  }

  /* Do we have a peer ? */
  if (nm_session->no_peer) {
    lua_pushnil(L);
    lua_pushstring(L, "snmp: bad peer");
    return 2;
  }

  /* Do we have a callback for asynch requests ? */
  if (req_mode == NM_SNMP_ASYNCH_REQ) {
    if ((ref_cb == -1) && (nm_session->defcb == -1)) {
      lua_pushnil(L);
      lua_pushstring(L, "snmp: bad callback");
      return 2;
    }
  }

  /* Construct the inform request using sysUpTime.0 and snmpTrapOID.0 */
  if (req_type == NM_SNMP_INFO_REQ) {
    if (nm_session->cmu_session->version == SNMP_VERSION_1) {
      lua_pushnil(L);
      lua_pushstring(L, "snmp: invalid config (inform)");
      return 2;
    }
    if (!(lua_isstring(L, trapOID))) {
      lua_pushnil(L);
      lua_pushstring(L, "snmp: bad trap oid");
      return 2;
    }
    pdu = snmp_pdu_create(SNMP_MSG_INFORM);
    if ((varlist = f_create_infovl((char *)lua_tostring(L, trapOID))) == NULL) {
      lua_pushnil(L);
      lua_pushstring(L, "snmp: bad trap oid");
      snmp_free_pdu(pdu);
      return 2;
    }
    pdu->variables = varlist;
    last_var = varlist->next_variable;
  } else {
    pdu = snmp_pdu_create(SNMP_MSG_SET);
  }

  /* Prepare single varbind or varbind list */
  if (!lua_istable(L, vlist)) {
    lua_pushnil(L);
    lua_pushstring(L, "snmp: bad name");
    snmp_free_pdu(pdu);
    return 2;
  }
  lua_pushstring(L, "oid");
  lua_gettable(L, vlist);
  if (!lua_isnil(L, -1)) {
    islist = FALSE;
    lua_pushvalue(L, vlist);
    if ((varlist = f_create_vlist(L, errs)) == NULL) {
      lua_pushnil(L);
      lua_pushstring(L, errs);
      snmp_free_pdu(pdu);
      return 2;
    }
    lua_remove(L, -1);
    if (pdu->variables)
          last_var->next_variable = varlist;
    else
      pdu->variables = varlist;
  } else {
    islist = TRUE;
    for (ind = 1; ; ind++) {
      lua_rawgeti(L, vlist, ind);
      if (lua_isnil(L, -1))
        break;
      if ((varlist = f_create_vlist(L, errs)) == NULL) {
        char eerrs[64];
        lua_pushnil(L);
        sprintf(eerrs, "%s in index %d", errs, ind);
        lua_pushstring(L, eerrs);
        snmp_free_pdu(pdu);
        return 2;
      }
      lua_remove(L, -1);
      if (pdu->variables)
        last_var->next_variable = varlist;
          else
            pdu->variables = varlist;
      last_var = varlist;
    }
  }
  /* Perform the request */
  if (req_mode == NM_SNMP_SYNCH_REQ)
    retval = nm_snmp_synch_req(L, nm_session, pdu, islist);
  else
    retval = nm_snmp_asynch_req(L, nm_session, pdu, islist, ref_cb, ref_magic);
  return retval;
}

/*-----------------------------------------------------------------------------
 *  nm_snmp_wait
 *
 *  Synopsis : snmp.wait(session)
 *  Lua Param: session
 *  Return   : nil on success, 
 *             error msg on error
 *  Function : wait for events for given session
 *----------------------------------------------------------------------------*/
static int nm_snmp_wait(lua_State *L) {
  Tsession *nm_session, *nxt_sess;

  /* session handle */
  if (lua_isnil(L,1) || (!lua_istable(L, 1))) {
    lua_pushstring(L, "snmp: bad session");
    return 1;
  }
  lua_pushstring(L, "internal");
  lua_gettable(L, -2);
  if (!lua_isuserdata(L, -1)) {
    lua_pushstring(L, "snmp: bad session");
    return 1;
  }

  nm_session = (Tsession *)lua_touserdata(L, -1);
  for (nxt_sess = nm_snmp_sessions; nxt_sess; nxt_sess = nxt_sess->next)
    if (nxt_sess == nm_session)
      break;
  if (nxt_sess == NULL) {
    lua_pushstring(L, "snmp: bad session");
    return 1;
  }

  /* Loop as long as requests are pending */
  while (nm_session->as_reqs)
    nm_snmp_event(L);

  return 0;
}


/*-----------------------------------------------------------------------------
 * Event handling
 *----------------------------------------------------------------------------*/
static int nm_snmp_synch_input(int op,
			       netsnmp_session * session,
			       int reqid, netsnmp_pdu *pdu, void *magic)
{
  struct synch_state *state = (struct synch_state *) magic;
  int             rpt_type;
  
  if (reqid != state->reqid && pdu && pdu->command != SNMP_MSG_REPORT) {
    return 0;
  }
  
  state->waiting = 0;
  
  if (op == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
    if (pdu->command == SNMP_MSG_REPORT) {
      rpt_type = snmpv3_get_report_type(pdu);
      if (SNMPV3_IGNORE_UNAUTH_REPORTS ||
	  rpt_type == SNMPERR_NOT_IN_TIME_WINDOW) {
	state->waiting = 1;
      }
      state->pdu = NULL;
      state->status = STAT_ERROR;
      session->s_snmp_errno = rpt_type;
      SET_SNMP_ERROR(rpt_type);
    } else if (pdu->command == SNMP_MSG_RESPONSE) {
      /*
       * clone the pdu to return to snmp_synch_response 
       */
      state->pdu = snmp_clone_pdu(pdu);
      state->status = STAT_SUCCESS;
      session->s_snmp_errno = SNMPERR_SUCCESS;
    }
  } else if (op == NETSNMP_CALLBACK_OP_TIMED_OUT) {
    state->pdu = NULL;
    state->status = STAT_TIMEOUT;
    session->s_snmp_errno = SNMPERR_TIMEOUT;
    SET_SNMP_ERROR(SNMPERR_TIMEOUT);
  } else if (op == NETSNMP_CALLBACK_OP_DISCONNECT) {
    state->pdu = NULL;
    state->status = STAT_ERROR;
    session->s_snmp_errno = SNMPERR_ABORT;
    SET_SNMP_ERROR(SNMPERR_ABORT);
  }
  
  return 1;
}

/*-----------------------------------------------------------------------------
 *  nm_snmp_event
 *
 *  Synopsis : snmp.event()
 *  Lua Param: none
 *  Return   : none
 *  Function : wait for a single event
 *----------------------------------------------------------------------------*/
static int nm_snmp_event(lua_State *L) {
  /* Se tenho request(s) pendente(s), verifica sockets */

  if ((nm_snmp_async_reqs) || (nm_snmp_sync_reqs)) {
    int numfds, count;
    fd_set fdset;
    struct timeval timeout, *tvp;
    int block;
    int gotone = 0;

    while (!gotone) {
      numfds = 0;
      FD_ZERO(&fdset);
      block = 0;

      tvp = &timeout;
      timerclear(tvp);
      tvp->tv_usec = 500000L;

      snmp_select_info(&numfds,&fdset,tvp,&block);
      count = select(numfds, &fdset, 0, 0, tvp);
      if (count > 0) {
        snmp_read(&fdset);
        gotone = 1;
      } else {
        switch (count) {
        case 0 :
          snmp_timeout();
          gotone = 1;
          break;

        case -1:
          if (errno == EINTR)
            perror("select");
          break;
          perror("select");
        default: /* ??? */
          fprintf(stderr,"snmp: error during event handling (select)\n");
          gotone = 1;
          break;
        }
      }
    }
  }
  /* Check for trap events */
  if (nm_snmp_ntraps) {
#ifdef USE_SNMPTRAPD
    char *buf = malloc(NM_SNMP_TRAP_BUFLEN);
    int rxlen;
    if ((rxlen = nm_trap_event(buf, NM_SNMP_TRAP_BUFLEN)) > 0) {
      nm_in_usr_cback = 1;
      nm_snmp_trap(L, buf, rxlen);
      nm_in_usr_cback = 0;
    }
    free(buf);
#else
    struct sockaddr_in from;
    int length;

    length = PACKET_LENGTH;
    if (nm_trap_event(nm_snmp_trappkt, &length, &from)) {
      nm_in_usr_cback = 1;
      nm_snmp_trap(L, nm_snmp_trappkt,length,&from);
      nm_in_usr_cback = 0;
    }
#endif
  } 

  /* Something to close ? */
  if (nm_close_list) {
    CloseList *pclose, *freeme;
    pclose = nm_close_list;
    while (pclose) {
      snmp_close(pclose->cmu_session);
      freeme = pclose;
      pclose = pclose->next;
      free((char *)freeme);
    }
    nm_close_list = NULL;
  }

  return 0;
}

/*-----------------------------------------------------------------------------
 *  nm_snmp_eventloop
 *
 *  Synopsis : snmp.eventloop()
 *  Lua Param: none
 *  Return   : none
 *  Function : wait for multiple pending events
 *----------------------------------------------------------------------------*/
static int nm_snmp_eventloop(lua_State *L) {
  while ((nm_snmp_async_reqs) || (nm_snmp_ntraps))
    nm_snmp_event(L);
  return 0;
}

/*-----------------------------------------------------------------------------
 * Treatment of synchronous and asynchronous requests and responses.
 *----------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
 *  nm_snmp_pushrsp
 *
 *  Synopsis : -
 *  Lua Param: -
 *  Return   : op_status != success: nil + error msg + op_status
 *             op_status == success: 
 *               pdu->errstat == no_error: vbind or vlist
 *               pdu->errstat == error:    vbind or vlist + status + errindex
 *  Function : Pushes synchronous response of a request onto the stack
 *----------------------------------------------------------------------------*/
static int nm_snmp_pushrsp(lua_State *L, Tsession *nm_session, int op_status, struct snmp_pdu *pdu, int islist) {
  int retval;

  if (op_status != STAT_SUCCESS) {
    lua_pushnil(L);
    if (op_status == STAT_TIMEOUT){
      lua_pushstring(L, "snmp: timeout");
      lua_pushnumber(L, op_status);
      return 3;
    } else {
      lua_pushstring(L, "snmp: internal error - response status");
      //      lua_pushnumber(L, op_status);
      return 2;
    }
  }

  /* Check on response errors */
  if ((op_status = f_prim_err(pdu->errstat)) != SNMP_ERR_NOERROR) {
    int ind;

    /* Some error: Create the vbind or vlist + status + errindex on the stack */
    retval = f_create_vbind(L, islist, pdu->variables);
#ifdef REMOVE_THIS
    if (!islist && (nm_session->vbindmetatable == 1)){
      lua_pushlightuserdata(L, &nm_session->vbindmetatable);
      lua_gettable(L, LUA_REGISTRYINDEX);
      lua_setmetatable(L, -2);
    }
#endif
#if 1
    lua_getglobal(L, "snmp");
#else
    lua_pushstring(L, "snmp");
    lua_gettable(L, LUA_GLOBALSINDEX);
#endif
    lua_pushstring(L, "errtb");
    lua_gettable(L, -2);
    lua_remove(L, -2);
    lua_pushnumber(L, op_status);
    lua_gettable(L, -2);
    lua_remove(L, -2);
    if ((ind=pdu->errindex)){
      lua_pushnumber(L, ind);
      return retval + 2;
    } else {
#ifdef REMOVE_THIS
      lua_pushnil(L);
      return retval + 2;
#else
      return retval + 1;
#endif
    }
  } else {
    /* No error: Create vbind or vlist on the stack */
    retval =  f_create_vbind(L, islist, pdu->variables);
    if (!islist && (nm_session->vbindmetatable == 1)){
      lua_pushlightuserdata(L, &nm_session->vbindmetatable);
      lua_gettable(L, LUA_REGISTRYINDEX);
      lua_setmetatable(L, -2);
    }
#ifdef REMOVE_THIS
    lua_pushnil(L);
    lua_pushnil(L);
    return retval + 2;
#else
    return retval;
#endif
  }
}

/*-----------------------------------------------------------------------------
 *  nm_snmp_synch_req
 *
 *  Synopsis : -
 *  Lua Param: none
 *  C Param  : session, request pdu, istlist indicates expected result (vbind or vlist)
 *  Return   : see nm_snmp_push_rsp
 *  Function : Performs a synchronous request.
 *----------------------------------------------------------------------------*/
static int nm_snmp_synch_req(lua_State *L, Tsession *nm_session, struct snmp_pdu *pdu, int islist) {
  int op_status;
  struct synch_state *state;
  int retval;
  int _errno = 0;
  int _snmp_errno = 0;
  char *str;

  /* Pede o envio do pdu */
  state = &(nm_session->cmu_synch_state);
#if 0
  if (pdu->command == SNMP_MSG_INFORM)
    netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DEFAULT_PORT, 
		       SNMP_TRAP_PORT);
#endif
  if ((state->reqid = snmp_send(nm_session->cmu_session,pdu)) == 0) {
    snmp_error(nm_session->cmu_session, &_errno, &_snmp_errno, &str);
    fprintf(stderr, "errno=%d, snmp_errno=%d, errstr='%s'\n", _errno, _snmp_errno, str);
    free(str);
    snmp_free_pdu(pdu);
    lua_pushnil(L);
    lua_pushstring(L, "snmp: internal error - synch request id is 0");
    return 2;
  }

  /* Prepara estrutura de ctrl request (cmu) e aguarda a resposta */
  nm_session->synch_req = TRUE;
  nm_snmp_sync_reqs++;

  state->waiting = 1;
  while (state->waiting)
    nm_snmp_event(L);

  nm_session->synch_req = FALSE;
  nm_snmp_sync_reqs--;

  /* Prepara parametros de retorno na pilha de lua */
  op_status = state->status;
  if ((op_status == STAT_SUCCESS) && (state->pdu == NULL))
    op_status = STAT_ERROR;

  retval = nm_snmp_pushrsp(L, nm_session, op_status, state->pdu, islist);

  /* Preciso devolver o pdu de resposta */
  if (op_status == STAT_SUCCESS)
    snmp_free_pdu(state->pdu);

  return retval;
}


/*-----------------------------------------------------------------------------
 *  nm_snmp_asynch_req
 *
 *  Synopsis : -
 *  Lua Param: -
 *  C Param  : session, request pdu, istlist indicates expected result (vbind or vlist)
 *  Return   : see nm_snmp_push_rsp
 *  Function : Performs an asynchronous request
 *----------------------------------------------------------------------------*/
static int nm_snmp_asynch_req(lua_State *L, Tsession *nm_session, struct snmp_pdu *pdu, int islist, int ref_cb, int ref_magic) {
  int reqid;
  ReqList *req, *nxtreq;

  if ((reqid = snmp_send(nm_session->cmu_session,pdu)) == 0) {
    snmp_free_pdu(pdu);
    lua_pushnil(L);
    lua_pushstring(L, "snmp: internal error - asynch request id is 0");
    return 2;
  }

  /* Aloca estrutura de controle para o request assincrono */
  req = (ReqList *)malloc(sizeof(ReqList));
  if (req == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "snmp: internal error - asynch request allocation");
    return 2;
  }
  req->next = NULL;
  req->reqid = reqid;
  lua_pushlightuserdata(L, &req->reqcb);
  lua_pushvalue(L, ref_cb);
  lua_settable(L, LUA_REGISTRYINDEX);
  req->reqcb = ref_cb;
  lua_pushlightuserdata(L, &req->magic);
  lua_pushvalue(L, ref_magic);
  lua_settable(L, LUA_REGISTRYINDEX);
  req->magic = ref_magic;
  req->is_list = islist;

  /* Insere o request na fila da sessao */
  nm_session->as_reqs++;

  if (nm_session->as_reqs_lst == NULL)
    nm_session->as_reqs_lst = req;
  else {
    for (nxtreq = nm_session->as_reqs_lst; ; nxtreq = nxtreq->next)
      if (nxtreq->next == NULL)
        break;
    nxtreq->next = req;
  }
  nm_snmp_async_reqs++;

  lua_pushnumber(L, reqid);
  return 1;
}

/*-----------------------------------------------------------------------------
 *  nm_snmp_asynch_rsp
 *
 *  Synopsis : -
 *  Lua Param: - 
 *  Return   : request id
 *  Function : Calls the user provided callback function with the following
 *             parameters:
 *             vbind or vlist + status + errindex + session + request-id
 *             Performs retries and timeout as well.
 *----------------------------------------------------------------------------*/
static int nm_snmp_asynch_rsp(Tsession *nm_session, int reqid, int op, struct snmp_pdu *pdu) {
  ReqList *prvreq, *req;
  lua_State *L = nm_session->L;
  int op_status;
  int retval;

  /* Find the session for this response */
  prvreq = NULL;
  for (req = nm_session->as_reqs_lst; req ; req = req->next) {
    if (req->reqid == reqid ) {
      if (prvreq == NULL)
        nm_session->as_reqs_lst = req->next;
      else
        prvreq->next = req->next;
      break;
    }
    prvreq = req;
  }
  if ( req == NULL ) {
    return 0;
  }
  nm_snmp_async_reqs--;
  nm_session->as_reqs--;
  
  /* Get the callback */
  if (req->reqcb == -1) {
    lua_pushlightuserdata(L, &nm_session->defcb);
    lua_gettable(L, LUA_REGISTRYINDEX);
  } else {
    lua_pushlightuserdata(L, &req->reqcb);
    lua_gettable(L, LUA_REGISTRYINDEX);
  }

  /* Verify result of request (ok or timeout) */
  if ((op == RECEIVED_MESSAGE) && (pdu != NULL) &&
      (pdu->command == SNMP_MSG_RESPONSE || pdu->command == SNMP_MSG_REPORT))
    op_status = STAT_SUCCESS;
  else
    if (op == TIMED_OUT)
      op_status = STAT_TIMEOUT;
    else
      op_status = STAT_ERROR;
  
  /* vbind + status + error_index on Lua stack */
  retval = nm_snmp_pushrsp(L, nm_session, op_status,pdu,req->is_list);

  while (retval < 3){
    lua_pushnil(L);
    retval = retval + 1;
  }

  /* request id on Lua stack */
  lua_pushnumber(L, reqid);

  /* session on Lua stack */
  lua_pushlightuserdata(L, &nm_session->lua_session);
  lua_gettable(L, LUA_REGISTRYINDEX);

  /* magic on Lua stack */
  if (req->magic != -1){
    lua_pushlightuserdata(L, &req->magic);
    lua_gettable(L, LUA_REGISTRYINDEX);
  } else {
    lua_pushnil(L);
  }

  /* Invoke Lua level callback */
  lua_call(L, retval + 3, 0);

  if (req->reqcb != -1 ){
    lua_pushlightuserdata(L, &req->reqcb);
    lua_pushnil(L);
    lua_settable(L, LUA_REGISTRYINDEX);
  }
  if (req->magic != -1){
    lua_pushlightuserdata(L, &req->magic);
    lua_pushnil(L);
    lua_settable(L, LUA_REGISTRYINDEX);
  }

  /* Finished: free this request */
  free((char *)req);

  return 1;

}

/*-----------------------------------------------------------------------------
 *  name nm_snmp_freereqs
 *
 *  Synopsis : -
 *  Lua Param: -
 *  Return   : -
 *  Function : Free all pending requests
 *----------------------------------------------------------------------------*/
static void nm_snmp_freereqs(Tsession *nm_session) {
  ReqList *nxtreq, *freeme;

  nxtreq = nm_session->as_reqs_lst;
  while (nxtreq) {
    nm_snmp_async_reqs--;
    freeme = nxtreq;
    nxtreq = nxtreq->next;
    free((char *)freeme);
  }
  nm_session->as_reqs_lst = NULL;
  nm_session->as_reqs = 0;
}

/*-----------------------------------------------------------------------------
 *  nm_snmp_callback
 *
 *  Synopsis : -
 *  Lua Param: - 
 *  Return   : see nm_snmp_asynch_rsp
 *  Function : Callback treatment.
 *----------------------------------------------------------------------------*/
static int nm_snmp_callback(int op, CmuSession *session, int reqid, struct snmp_pdu *pdu, void *magic) {
  int res;
  Tsession *nxt_sess;
  Tsession *nm_session = (Tsession *)magic;


  /* Is this a valid session */
  for (nxt_sess = nm_snmp_sessions; nxt_sess; nxt_sess = nxt_sess->next)
    if (nxt_sess == nm_session)
      break;
  if (nxt_sess == NULL)
    return 0;


  /* If synchronous request is pending - process this first */
  if (nm_session->synch_req)
    if (nm_snmp_synch_input(op,session,reqid,
			    pdu,(void *) &(nm_session->cmu_synch_state)) == 1) 
      return 1;

  /* Process responses to asynch requests */
  nm_in_usr_cback = 1;
  res = nm_snmp_asynch_rsp(nm_session,reqid,op,pdu);
  nm_in_usr_cback = 0;
  return res;
}

/*-----------------------------------------------------------------------------
 * Trap handling.
 *----------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
 *  nm_snmp_trap
 *
 *  Synopsis : -
 *  Lua Param: -
 *  C Param  : packet, packet-length, ip address of sender
 *  Return   : vbind, ip and session
 *  Function : Processes an incoming trap
 *----------------------------------------------------------------------------*/
#ifdef USE_SNMPTRAPD
static void nm_snmp_trap(lua_State *L, char *buf, int rxlen)
{
  Tsession *nm_session, *nxt_session;
  /* We step through all sessions that have a trap callback */
  for (nm_session = nm_snmp_sessions; nm_session; nm_session = nxt_session) {

    nxt_session = nm_session->next;
    
    if (nm_session->trapcb == -1)
      continue;
    
    /* Session has a trap callback */
    lua_pushlightuserdata(L, &nm_session->trapcb);
    lua_gettable(L, LUA_REGISTRYINDEX);
    lua_pushlightuserdata(L, &nm_session->lua_session);
    lua_gettable(L, LUA_REGISTRYINDEX);
    lua_pushstring(L, buf);
    lua_call(L, 2, 0);
  }
}

#else /* USE_SNMPTRAPD */

static void nm_snmp_trap(lua_State *L, u_char *packet, int length, struct sockaddr_in *from) {
  struct snmp_pdu *pdu;
  Tsession *nm_session, *nxt_session;
  size_t pktLen = length;
  int retval;
  Tsession *info_session = NULL; /* indica se manda response a um inform */

  /* Prepare a PDU to be filled from packet */
  pdu = (struct snmp_pdu *)calloc(1, sizeof(struct snmp_pdu));
  memcpy((char *)(pdu->agent_addr),(char *)&from->sin_addr.s_addr, sizeof(pdu->agent_addr));
  pdu->reqid = 0;
  pdu->variables = NULL;
  pdu->enterprise = NULL;
  pdu->enterprise_length = 0;

  nm_session = nm_snmp_sessions;

  if ((retval = snmp_parse(NULL, nm_session->cmu_session, pdu, packet, pktLen)) || 
      ((pdu->command != SNMP_MSG_TRAP) &&(pdu->command != SNMP_MSG_TRAP2) 
       && (pdu->command != SNMP_MSG_INFORM))) {
    fprintf(stderr,"luasnmp: invalid trap packet %d %d\n", retval, pdu->command);
    snmp_free_pdu(pdu);
    return;
  }

  /* Convert SNMPV1 trap into SNMPV2 trap */
  if (pdu->command == SNMP_MSG_TRAP) {
    f_trapconv(pdu);
  }

  /* Walk throught the session for further processing */
  for (nm_session = nm_snmp_sessions; nm_session; nm_session = nxt_session) {

    nxt_session = nm_session->next;
    /* Trap for this session ? */
    if (!(nm_session->no_peer)){
      /* peer 0.0.0.0 -> todos os traps */
      /* Get peer from packet */
      if (nm_session->peer_addr != *((u_long*) (pdu->agent_addr)))
        continue;
    }

    if (pdu->command == SNMP_MSG_INFORM) {
      if (nm_session->infocb == -1)
        continue;
      lua_pushlightuserdata(L, &nm_session->infocb);
      lua_gettable(L, LUA_REGISTRYINDEX);
      info_session = nm_session;
    } else {
      if (nm_session->trapcb == -1)
        continue;
      lua_pushlightuserdata(L, &nm_session->trapcb);
      lua_gettable(L, LUA_REGISTRYINDEX);
    }

    /* Construct the vbind list on Lua Stack */
    f_create_vbind(L, TRUE, pdu->variables);

    /* Push IP address on stack */
    {
      char s[32];
      sprintf(s, "%d.%d.%d.%d:%d", 
	      pdu->agent_addr[0], 
	      pdu->agent_addr[1], 
	      pdu->agent_addr[2], 
	      pdu->agent_addr[3], htons(from->sin_port));

      lua_pushstring(L, s);
    }
    lua_pushlightuserdata(L, &nm_session->lua_session);
    lua_gettable(L, LUA_REGISTRYINDEX);

    /* Invoke user supplied callback function */
    lua_call(L, 3, 0);
  }

  /* Check response upon inform request */
  if (info_session != NULL) {
    pdu->command = SNMP_MSG_RESPONSE;
    pdu->errstat = 0;
    pdu->errindex = 0;
    snmp_send(info_session->cmu_session,pdu);
    return;
  }

  /* Done. free the PDU now */
  snmp_free_pdu(pdu);
}
#endif
/*-----------------------------------------------------------------------------
 * nm_snmp_sprintvar
 *
 *  Synopsis : snmp.sprint_variable(vb) 
 *  Lua Param: variable binding
 *  C Param  : -
 *  Return   : -
 *  Function : Pretty print a variable binding
 *----------------------------------------------------------------------------*/
static int nm_snmp_sprint(lua_State *L, int what)
{
  struct variable_list *vlist;
  char errs[128];
  char *buf;
  int buflen = 1024;
  oid objid[NMAX_SUBID];
  int objidlen;
  int len = 0;

  vlist = f_create_vlist_from_objid(L, objid, &objidlen, errs);
  if (vlist == NULL){
    lua_pushstring(L, errs);
    return 1;
  }
  buf = calloc(buflen, 1);
  switch(what){
  case NM_SNMP_PRINT_VALUE:
    len = snprint_value(buf, buflen, objid, objidlen, vlist);
    break;
  case NM_SNMP_PRINT_VARIABLE:
    len = snprint_variable(buf, buflen, objid, objidlen, vlist);
    break;
  }
  free(vlist->name);
  free(vlist->val.string);
  free(vlist);
  if (len == -1){
    free(buf);
    lua_pushstring(L, "snmp: cannot print.");
    return 1;
  }
  lua_pushlstring(L, buf, len);
  free(buf);
  return 1;
}
static int nm_snmp_sprint_value(lua_State *L){
  return nm_snmp_sprint(L, NM_SNMP_PRINT_VALUE);
}
static int nm_snmp_sprint_variable(lua_State *L){
  return nm_snmp_sprint(L, NM_SNMP_PRINT_VARIABLE);
}


/*-----------------------------------------------------------------------------
 * Initialisation Functions
 *----------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------
 *  nm_snmp_inittrap
 *
 *  Synopsis : snmp.inittrap(straps-program)
 *  Lua Param: straps-program - SNMP forwarding daemon
 *  Return   : nil on success or error msg on failure
 *  Function : Init trap handling
 *----------------------------------------------------------------------------*/
static int nm_snmp_inittrap(lua_State *L) {

#ifdef USE_SNMPTRAPD
  nm_snmp_trap_port = luaL_optint(L, 1, SNMP_TRAP_PORT);
  return 0;
#else

  if (nm_snmp_init_done){
    lua_pushstring(L, "snmp: already initialised");
    return 1;
  }
  
  strcpy(nm_snmp_straps, luaL_optstring(L, 1, "./bin/straps"));
  nm_snmp_straps_port = luaL_optint(L, 2, SNMP_TRAP_PORT);
      
  /* Init sysUpTime */
  f_uptime();
  nm_snmp_init_done = 1;
  lua_pushnil(L);
  return 1;
#endif
}


/*-----------------------------------------------------------------------------
 *  nm_snmp_config_parser
 *
 *  Synopsis : -
 *  Lua Param: -
 *  C Param  : token, line - token and value from config file parser.
 *  Return   : -
 *  Function : Parses snmp.conf tokens for luasnmp
 *----------------------------------------------------------------------------*/
static void nm_snmp_config_parser(const char *token, char *line)
{
  lua_pushlightuserdata(lua_ref, &lua_ref);
  lua_gettable(lua_ref, LUA_REGISTRYINDEX);
  lua_pushstring(lua_ref, token);
  lua_pushstring(lua_ref, line);
  lua_call(lua_ref, 2, 0);
}

/*-----------------------------------------------------------------------------
 *  nm_snmp_init
 *
 *  Synopsis : snmp.init(config_table, handler)
 *  Lua Param: configs_table - table with snmp.conf tokens to handle
 *             handler - config parser (handler).
 *  Return   : nil on success or error msg on failure
 *  Function : Init trap handling
 *----------------------------------------------------------------------------*/
static int nm_snmp_init(lua_State *L){
  int i;
  struct config_line *cl;

  lua_ref = L;

  if (lua_isnil(L, 1)){
    lua_settop(L, -1);
    return 0;
  }
  for (i=1; ;i++){
    lua_rawgeti(L, 1, i);
    if (lua_isnil(L, -1))
      break;
    cl = register_config_handler("snmp", lua_tostring(L, -1), nm_snmp_config_parser, NULL, NULL);
    lua_remove(L, -1);
    if (!cl){
      lua_pushstring(L, "snmp init: bad config registration.");
      return 1;
    }
  }
  lua_pushlightuserdata(L, &lua_ref);
  lua_pushvalue(L, 2);
  if (lua_isnil(L, -1)){
    lua_remove(L, -1);
    lua_pushstring(L, "snmp init: bad config parser.");
    return 1;
  }
  lua_settable(L, LUA_REGISTRYINDEX);

  /* Init varbind metatable reference */
  lua_pushlightuserdata(L, &vbindmetatable);
#if 1
  lua_getglobal(L, "snmp");
#else
  lua_pushstring(L, "snmp");
  lua_gettable(L, LUA_GLOBALSINDEX);
#endif
  lua_pushstring(L, "__vbindmetatable");
  lua_gettable(L, -2);
  if (lua_isnil(L, -1))
    printf("WHATISTHIS\n");
  lua_remove(L, -2);
  lua_settable(L, LUA_REGISTRYINDEX);
  vbindmetatable = 1;
  snmp_sess_init(&nm_cmu_session);
  init_snmp("snmpapp");
  return 0;
}
/*-----------------------------------------------------------------------------
 * nm_snmp_getversion
 *----------------------------------------------------------------------------*/
int nm_snmp_getversion(lua_State *L)
{
  lua_pushstring(L, netsnmp_get_version());
  return 1;
}

/*-----------------------------------------------------------------------------
 * nm_snmp_createkey
 *
 * key, err = snmp.createkey(session, passphrase [,hashtype])
 *----------------------------------------------------------------------------*/
int nm_snmp_createkey(lua_State *L)
{
  Tsession *nm_session;
  u_char *s_hashtype;
  char *passwd;
  char hashtype_buf[512];
  oid *hashtype;
  u_char keybuf[SNMP_MAXBUF_SMALL];
  size_t hashtype_len = 0, passwd_len = 0;
  size_t keybuf_len = SNMP_MAXBUF_SMALL;
  int retval;
  netsnmp_session *cmu_session;

  /* Get the internal session from external session */
  if (!lua_istable(L, 1)){
    lua_pushnil(L);
    lua_pushstring(L, "snmp: bad session");
    return 2;
  }
  lua_pushvalue(L, 1);
  nm_session = nm_snmp_getsession(L);
  if (nm_session == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "snmp: bad session");
    return 2;
  }
  cmu_session = nm_session->cmu_session;

  /* get password */
  passwd = (char *)luaL_checkstring(L, 2);
  if ((passwd_len = strlen(passwd)) < USM_LENGTH_P_MIN){
    lua_pushnil(L);
    lua_pushstring(L, "snmp: password too short");
    return 2;
  }

  /* OID for hashtype */
  s_hashtype = (u_char *) luaL_optstring(L, 3, NULL);
  if (s_hashtype != NULL){
    /* Generate the OID */
    hashtype_len = f_str2oid((oid *)hashtype_buf, (char *) s_hashtype, NMAX_SUBID);
    hashtype = (oid *)hashtype_buf;
  } else {
    hashtype = cmu_session->securityAuthProto;
    hashtype_len = cmu_session->securityAuthProtoLen;
  }
  /* Generate the key */
  if ((retval = generate_Ku((const oid *)hashtype, hashtype_len, (u_char *) passwd, 
			    passwd_len, keybuf, &keybuf_len)) != SNMPERR_SUCCESS){
    lua_pushnil(L);
    lua_pushstring(L, "snmp: key generation error");
    return 2;
  }

  /* O.k. return the key as string */
  lua_pushlstring(L, (char*) keybuf, keybuf_len);
  lua_pushnumber(L, keybuf_len);
  return 2;
}

/*-----------------------------------------------------------------------------
 * nm_snmp_createlocalkey
 *
 * key, err = snmp.createlocalkey(session, ku, [,hashtype] [,engineid])
 *----------------------------------------------------------------------------*/
int nm_snmp_createlocalkey(lua_State *L)
{
  Tsession *nm_session;
  char *s_hashtype;
  char hashtype_buf[512];
  size_t hashtype_len = 0;
  oid *hashtype;
  u_char localkeybuf[SNMP_MAXBUF_SMALL];
  size_t localkeybuf_len = SNMP_MAXBUF_SMALL;
  u_char *keybuf;
  size_t keybuf_len = SNMP_MAXBUF_SMALL;
  u_char *engineID;
  size_t engineID_len;
  int retval;
  netsnmp_session *cmu_session;

  /* Get the internal session from external session */
  lua_pushvalue(L, 1);
  nm_session = nm_snmp_getsession(L);
  if (nm_session == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "snmp: bad session");
    return 2;
  }
  cmu_session = nm_session->cmu_session;

  /* key */
  keybuf = (u_char *)luaL_checklstring(L, 2, &keybuf_len);

  /* OID for hashtype */
  s_hashtype = (char*) luaL_optstring(L, 3, NULL);
  if (s_hashtype != NULL){
    hashtype_len = f_str2oid((oid *)hashtype_buf, s_hashtype, NMAX_SUBID);
    hashtype = (oid *)hashtype_buf;
  } else {
    hashtype_len = cmu_session->securityAuthProtoLen;
    hashtype = cmu_session->securityAuthProto;
  }

  /* engineID */
  engineID = (u_char *) luaL_optlstring(L, 4, NULL, &engineID_len);
  if (engineID == NULL) {
    engineID = cmu_session->contextEngineID;
    engineID_len = cmu_session->contextEngineIDLen;
  }
  
  /* Generate the key */
  if ((retval = generate_kul((const oid*)hashtype, hashtype_len, 
			     engineID, engineID_len,
			     keybuf, keybuf_len,
			     localkeybuf, &localkeybuf_len)) != SNMPERR_SUCCESS){
    lua_pushnil(L);
    lua_pushstring(L, "snmp: key generation error");
    return 2;
  }
  lua_pushlstring(L, (char *)localkeybuf, localkeybuf_len);
  lua_pushnumber(L, localkeybuf_len);
  return 2;
}

/*-----------------------------------------------------------------------------
 * nm_snmp_encode_keychange
 *
 * keychange, err = encode_keychange(oldkul, newkul, [,hashtype])
 *----------------------------------------------------------------------------*/
int nm_snmp_keychange(lua_State *L)
{
  Tsession *nm_session;
  char *s_hashtype;
  char hashtype_buf[512];
  size_t hashtype_len = 0;
  oid *hashtype;
  u_char *oldkeybuf;
  size_t oldkeybuf_len = SNMP_MAXBUF_SMALL;
  u_char *newkeybuf;
  size_t newkeybuf_len = SNMP_MAXBUF_SMALL;
  u_char keychange[SNMP_MAXBUF_SMALL];
  size_t keychange_len = SNMP_MAXBUF_SMALL;
  netsnmp_session *cmu_session;
  int retval;
  
  /* Get the internal session from external session */
  lua_pushvalue(L, 1);
  nm_session = nm_snmp_getsession(L);
  if (nm_session == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "snmp: bad session");
    return 2;
  }
  cmu_session = nm_session->cmu_session;

  /* old key */
  oldkeybuf = (u_char *)luaL_checklstring(L, 2, &oldkeybuf_len);

  /* new key */
  newkeybuf = (u_char *)luaL_checklstring(L, 3, &newkeybuf_len);

  /* OID for hashtype */
  s_hashtype = (char*) luaL_optstring(L, 4, NULL);
  if (s_hashtype != NULL){
    hashtype_len = f_str2oid((oid *)hashtype_buf, s_hashtype, NMAX_SUBID);
    hashtype = (oid *)hashtype_buf;
  } else {
    hashtype_len = cmu_session->securityAuthProtoLen;
    hashtype = cmu_session->securityAuthProto;
  }

  if ((retval = encode_keychange(hashtype, hashtype_len,
				 oldkeybuf, oldkeybuf_len,
				 newkeybuf, newkeybuf_len,
				 keychange, &keychange_len)) != SNMPERR_SUCCESS){
    lua_pushnil(L);
    lua_pushstring(L, "snmp: keychange generation error");
  }

  lua_pushlstring(L, (char*) keychange, keychange_len);
  lua_pushnumber(L, keychange_len);
  return 2;
}

/*-----------------------------------------------------------------------------
 * nm_snmp_details
 *
 * value, err = snmp.details(session)
 *----------------------------------------------------------------------------*/
int nm_snmp_sessiondetails(lua_State *L)
{
  Tsession *nm_session;
  netsnmp_session *cmu_session;

  /* Get the internal session from external session */
  lua_pushvalue(L, 1);
  nm_session = nm_snmp_getsession(L);
  if (nm_session == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "snmp: bad session");
    return 2;
  }
  cmu_session = nm_session->cmu_session;

  lua_newtable(L);
  lua_pushstring(L, "contextEngineID");
  lua_pushlstring(L, (const char*) cmu_session->contextEngineID,
		  cmu_session->contextEngineIDLen);
  lua_settable(L, -3);

  lua_pushstring(L, "contextEngineIDLen");
  lua_pushnumber(L, cmu_session->contextEngineIDLen);
  lua_settable(L, -3);
  
  lua_pushstring(L, "securityEngineID");
  lua_pushlstring(L, (const char*) cmu_session->securityEngineID,
		  cmu_session->contextEngineIDLen);
  lua_settable(L, -3);

  lua_pushstring(L, "securityEngineIDLen");
  lua_pushnumber(L, cmu_session->securityEngineIDLen);
  lua_settable(L, -3);
  
  lua_pushstring(L, "engineBoots");
  lua_pushnumber(L, cmu_session->engineBoots);
  lua_settable(L, -3);

  lua_pushstring(L, "engineTime");
  lua_pushnumber(L, cmu_session->engineTime);
  lua_settable(L, -3);
  
  lua_pushstring(L, "isAuthoritative");
  lua_pushnumber(L, cmu_session->isAuthoritative);
  lua_settable(L, -3);
  
  return 1;
}
#if REMOVE_THIS
/*-----------------------------------------------------------------------------
 * nm_snmp_usmpassword
 * 
 * Synopsis  : snmp.usmpassword(session, oldpw, newpw, flag [,user] [,ctxid])
 * Lua Param : session - reference to a valid session
 *             oldpw, newpw - string with old and new password
 *             flag - "a" auth, "p" priv, "ap" both
 *             user - optional string containing the user - if not given
 *                    takes the user of the current session
 *             ctxid - optional context engine id
 * Return    : nil or error string
 * Function  : Change a user's password
 *----------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------
 * nm_snmp_usmpassword snmp.usmpassword(session, old, new, flag [,user] [,ctxid])
 * nm_snmp_usmkey snmp.usmkey(session, flag [,user] [,ctxid])
 * nm_snmp_usmuser snmp.usmuser(session, user [,ctxid])
 * nm_snmp_usmclone snmp.usmclone(session, user, fromuser [,ctxid])
 * nm_snmp_usmdelete snmp.usmdelete(session, user [,ctxid])
 * 
 *----------------------------------------------------------------------------*/
int nm_snmp_usmpassword(lua_State *L)
{
  Tsession *nm_session;    
  netsnmp_pdu *pdu = NULL;

  netsnmp_session *cmu_session;
  char *oldpass = NULL, *newpass = NULL;
  int doauth = 0, dopriv = 0;
  char *user = NULL;
  const char *flag;
  int rval;
  size_t name_length = USM_OID_LEN;
  size_t name_length2 = USM_OID_LEN;

  u_char 
    oldKu[SNMP_MAXBUF_SMALL],
    newKu[SNMP_MAXBUF_SMALL],
    oldkul[SNMP_MAXBUF_SMALL],
    newkul[SNMP_MAXBUF_SMALL],
    oldkulpriv[SNMP_MAXBUF_SMALL],
    newkulpriv[SNMP_MAXBUF_SMALL],
    keychange[SNMP_MAXBUF_SMALL],
    keychangepriv[SNMP_MAXBUF_SMALL];

  size_t
    oldKu_len = SNMP_MAXBUF_SMALL,
    newKu_len = SNMP_MAXBUF_SMALL,
    oldkul_len = SNMP_MAXBUF_SMALL,
    newkul_len = SNMP_MAXBUF_SMALL,
    oldkulpriv_len = SNMP_MAXBUF_SMALL,
    newkulpriv_len = SNMP_MAXBUF_SMALL,
    keychange_len = SNMP_MAXBUF_SMALL,
    keychangepriv_len = SNMP_MAXBUF_SMALL;

  /* Get the internal session from external session */
  if (!lua_istable(L, 1)){
    lua_pushstring(L, "snmp: bad session");
    return 1;
  } else {
    lua_pushvalue(L, 1);
    nm_session = nm_snmp_getsession(L);
    cmu_session = nm_session->cmu_session;
    if (nm_session == NULL) {
      lua_pushnil(L);
      lua_pushstring(L, "snmp: bad session");
      return 2;
    }
  }

  /* Read old password */
  oldpass = (char *) luaL_checkstring(L, 2);
  if (strlen(oldpass) < USM_LENGTH_P_MIN){
    lua_pushstring(L, "snmp: old password too short");
    lua_error(L);
  }

  /* Read new password */
  newpass = (char *) luaL_checkstring(L, 3);
  if (strlen(newpass) < USM_LENGTH_P_MIN){
    lua_pushstring(L, "snmp: new password too short");
    lua_error(L);
  }

  /* Change flag parameter: if omitted auth and priv password only */
  flag = luaL_optstring(L, 4, "ap");
  if (strchr(flag, 'a'))
    doauth = 1;
  if (strchr(flag, 'p'))
    dopriv = 1;
  if ((doauth + dopriv) == 0){
    lua_pushstring(L, "snmp: bad change flag");
    lua_error(L);
  }

  /* Get user: if omitted take user from session */
  user = (char *) luaL_optstring(L, 5, (const char *) cmu_session->securityName);

  usmUserEngineID    = cmu_session->contextEngineID;
  usmUserEngineIDLen = cmu_session->contextEngineIDLen;


  if ((rval = generate_Ku(cmu_session->securityAuthProto,
			  cmu_session->securityAuthProtoLen,
			  (u_char *) oldpass, strlen(oldpass),
			  oldKu, &oldKu_len)) != SNMPERR_SUCCESS){
    lua_pushstring(L, "snmp: generating old Ku failed");
    lua_error(L);
  }

  if ((rval = generate_Ku(cmu_session->securityAuthProto,
			  cmu_session->securityAuthProtoLen,
			  (u_char *) newpass, strlen(newpass),
			  newKu, &newKu_len)) != SNMPERR_SUCCESS){
    lua_pushstring(L, "snmp: generating new Ku failed");
    lua_error(L);
  }

  if ((rval = generate_kul(cmu_session->securityAuthProto,
			   cmu_session->securityAuthProtoLen,
			   cmu_session->contextEngineID, cmu_session->contextEngineIDLen,
			   oldKu, oldKu_len, oldkul, &oldkul_len)) != SNMPERR_SUCCESS){

    lua_pushstring(L, "snmp: generation old Kul failed");
    lua_error(L);
  }
  if ((rval = generate_kul(cmu_session->securityAuthProto,
			   cmu_session->securityAuthProtoLen,
			   cmu_session->contextEngineID, cmu_session->contextEngineIDLen,
			   newKu, newKu_len, newkul, &newkul_len)) != SNMPERR_SUCCESS) {
    lua_pushstring(L, "snmp: generation old Kul failed");
    lua_error(L);
  }

  if (dopriv > 0){
    if (!cmu_session->securityPrivProto){
      lua_pushstring(L, "snmp: missing encryption type");
      lua_error(L);
    }
  } 
  
  if (ISTRANSFORM(cmu_session->securityPrivProto, DESPriv)) {
    /* DES uses a 128 bit key, 64 bits of which is a salt */
    oldkulpriv_len = newkulpriv_len = 16;
  }

  memcpy(oldkulpriv, oldkul, oldkulpriv_len);
  memcpy(newkulpriv, newkul, newkulpriv_len);

  if (doauth)
    if ((rval = encode_keychange(cmu_session->securityAuthProto,
				 cmu_session->securityAuthProtoLen,
				 oldkul, oldkul_len,
				 newkul, newkul_len,
				 keychange, &keychange_len)) != SNMPERR_SUCCESS) {
      lua_pushstring(L, "snmp: keychange encoding failure");
      lua_error(L);
    }

  /* which is slightly different for encryption if lengths are
     different */
  if (dopriv)
    if ((rval = encode_keychange(cmu_session->securityAuthProto,
				 cmu_session->securityAuthProtoLen,
				 oldkulpriv, oldkulpriv_len,
				 newkulpriv, newkulpriv_len,
				 keychangepriv, &keychangepriv_len)) != SNMPERR_SUCCESS){
      lua_pushstring(L, "snmp: keychange encoding failed");
      lua_error(L);
    }

  if (doauth) {
    f_setup_oid(authKeyChange, &name_length,
		usmUserEngineID, usmUserEngineIDLen,
		cmu_session->securityName);
    snmp_pdu_add_variable(pdu, authKeyChange, name_length,
			  ASN_OCTET_STR, keychange, keychange_len);
  }
  if (dopriv) {
    f_setup_oid(privKeyChange, &name_length2,
		usmUserEngineID, usmUserEngineIDLen,
		cmu_session->securityName);
    snmp_pdu_add_variable(pdu, privKeyChange, name_length2,
			  ASN_OCTET_STR,
			  keychangepriv, keychangepriv_len);
  }

  rval = nm_snmp_synch_req(L, nm_session, pdu, 1);
       
  return rval;
}
#endif

#ifndef REMOVE_THIS
/*-----------------------------------------------------------------------------
 * nm_snmp_remove_user_from_list
 *
 *  Synopsis : snmp.remove_user_from_list(session)
 *  Lua Param: session
 *  Return   : true on success, 
 *             nil + error msg on failure
 *  Function : Remove given session's user from net-snmp userList.
 *  Example:   res, err = sess:remove_user_from_list(vlist) 
 *----------------------------------------------------------------------------*/
static int nm_snmp_remove_user_from_list(lua_State *L){

  Tsession *nm_session;
  struct usmUser *user;
  char *username;

  /* Get the internal session from external session */
  if (!lua_istable(L, 1)){
    lua_pushnil(L);
    lua_pushstring(L, "snmp: bad session");
    return 2;
  }
  username = (char*) lua_tostring(L, -1);
  /* Get the internal session from external session */
  lua_pushvalue(L, 1);
  nm_session = nm_snmp_getsession(L);
  if (nm_session == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "snmp: bad session");
    return 2;
  }
  if (username == NULL)
    username = nm_session->cmu_session->securityName;

  user = usm_get_user(nm_session->cmu_session->securityEngineID, 
                      nm_session->cmu_session->securityEngineIDLen, 
                      username);
  if (user == NULL){
    lua_pushnil(L);
    lua_pushstring(L, "snmp: user not found in list");
    return 2;
  } 
  usm_remove_user(user);
  usm_free_user(user);
  lua_pushboolean(L, 1);
  return 1;
}
#endif
/*-----------------------------------------------------------------------------
 * nm_snmp_register
 *
 *  Synopsis : -
 *  Lua Param: -
 *  Return   : snmp namespace table
 *  Function : Register snmp module
 *----------------------------------------------------------------------------*/
#ifdef REMOVE_THIS
void nm_snmp_register(void) {
  lua_register("nm_snmp_open",nm_snmp_open);
  lua_register("snmp_close",nm_snmp_close);
  lua_register("snmp_get",nm_snmp_get);
  lua_register("snmp_getnext",nm_snmp_getnext);
  lua_register("snmp_set",nm_snmp_set);
  lua_register("snmp_getbulk",nm_snmp_getbulk);
  lua_register("snmp_inform",nm_snmp_inform);
  lua_register("snmp_asynch_get",nm_snmp_asynch_get);
  lua_register("snmp_asynch_getnext",nm_snmp_asynch_getnext);
  lua_register("snmp_asynch_set",nm_snmp_asynch_set);
  lua_register("snmp_asynch_getbulk",nm_snmp_asynch_getbulk);
  lua_register("snmp_asynch_inform",nm_snmp_asynch_inform);
  lua_register("snmp_wait",nm_snmp_wait);
  lua_register("snmp_idle",nm_snmp_event);
}
#endif

static const luaL_Reg funcs[] = {
  {"inittrap", nm_snmp_inittrap},
  {"gettrapd", nm_snmp_gettrapd},
  {"init", nm_snmp_init},
  {"_open", nm_snmp_open},
  {"close", nm_snmp_close},
  {"get", nm_snmp_get},
  {"getnext", nm_snmp_getnext},
  {"getbulk", nm_snmp_getbulk},
  {"asynch_get", nm_snmp_asynch_get},
  {"asynch_getnext", nm_snmp_asynch_getnext},
  {"asynch_getbulk", nm_snmp_asynch_getbulk},
  {"set", nm_snmp_set},
  {"asynch_set", nm_snmp_asynch_set},
  {"inform", nm_snmp_inform},
  {"asynch_inform", nm_snmp_asynch_inform},
  {"wait", nm_snmp_wait},
  {"event", nm_snmp_event},
  {"idle", nm_snmp_eventloop},
  {"loop", nm_snmp_eventloop},
  {"sprint_variable", nm_snmp_sprint_variable},
  {"sprint_value", nm_snmp_sprint_value},
  {"getversion", nm_snmp_getversion},
  {"createkey", nm_snmp_createkey}, 
  {"createlocalkey", nm_snmp_createlocalkey}, 
  {"keychange", nm_snmp_keychange},
  {"details", nm_snmp_sessiondetails},
  {"removeuser", nm_snmp_remove_user_from_list},
#ifdef REMOVE_THIS
  {"usmpassword", nm_snmp_usmpassword},
#endif
  {NULL, NULL}
};

extern const luaL_Reg mibfuncs[];

#define luaopen_snmpcore luaopen_snmp_core

LUALIB_API int luaopen_snmp_core(lua_State *L) {
#if LUA_VERSION_NUM > 501
  lua_newtable(L);                     /* mtab */
  luaL_setfuncs(L, funcs, 0); 
  lua_pushvalue(L, -1);                /* mtab, mtab */
  lua_setglobal(L, MYNAME);            /* mtab */
#else
  luaL_register(L, MYNAME, funcs);     /* mtab */
#endif
  lua_pushliteral(L, "version");       /* mtab.version = ... */
  lua_pushliteral(L, MYVERSION);
  lua_rawset(L, -3);
  lua_pushliteral(L, "_VERSION");      /* mtab._VERSION = ... */
  lua_pushliteral(L, MYVERSION);
  lua_rawset(L, -3);
  lua_pushliteral(L, "_SYSTEM");       /* mtab._SYSTEM = ... */
  lua_pushliteral(L, MYSYSTEM);
  lua_rawset(L, -3);
  except_open(L);                      /* mtab */
  lua_pushliteral(L, "mib");           /* 'mib', mtab */
  lua_newtable(L);                     /* tab, 'mib', mtab */
#if LUA_VERSION_NUM > 501
  luaL_setfuncs(L, mibfuncs, 0);
#else
  luaL_register(L, NULL, mibfuncs);    /* tab.<funcs> ... */
#endif
  lua_settable(L, -3);                 /* mtab */
  c64_open(L);                         
  return 1;
}
/*-----------------------------------------------------------------------------
 * Helpers 
 *----------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
 * nm_snmp_getsession
 *
 *  Synopsis : -
 *  Lua Param: -
 *  Return   : Luasnmp session or nil
 *  Function : Retrieve Luasnmp session 
 *----------------------------------------------------------------------------*/
static Tsession *nm_snmp_getsession(lua_State *L) {
  Tsession *nm_session,*nxt_sess;

  lua_pushstring(L, "internal");
  lua_rawget(L, -2);
#if REMOVE_THIS
  lua_gettable(L, -2);
#endif
  if (!lua_isuserdata(L,-1))
    return  NULL;
  nm_session = lua_touserdata(L, -1);
  lua_pop(L, 2); /* pop C-session and Lua session */
  /* leu: do we need this loop ? */
  for (nxt_sess = nm_snmp_sessions; nxt_sess; nxt_sess = nxt_sess->next)
    if (nxt_sess == nm_session)
      break;
  return(nxt_sess);
}

