/*-----------------------------------------------------------------------------
 * nm_trap.c
 *
 * Funcoes auxiliares para recepcao de TRAPS
 *
 * A recepcao de traps, em ambientes "UNIX" e' realizada atraves
 * do uso do daemon "straps" (recebe e reencaminha traps SNMP enviadas
 * para a porta privilegiada 162). 
 *
 * Quando a API LUAMAN for portada para ambiente Windows, reestudar o caso.
 *-----------------------------------------------------------------------------*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>

#include <sys/time.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>

#include "nm_trap.h"

#ifndef USE_SNMPTRAPD
#ifndef _NFILE
#define _NFILE 20
#endif

#ifndef WIN32
#ifdef VFORK
extern pid_t vfork(void);
#endif
#endif
#endif /* USE_SNMPTRAPD */
/*-----------------------------------------------------------------------------
 * Local variables
 *----------------------------------------------------------------------------*/

static int nm_trap_sock = -1;  /* socket para a recepcao de traps */
#ifndef USE_SNMPTRAPD
static char straps_path[] = "/tmp/.straps";
static char straps_port[8];
static char *argv[3] = {NULL, NULL, 0};
#endif
/*-----------------------------------------------------------------------------
 * nm_trap_open
 *
 * Opens a socket for notifications from snmptrapd.
 *----------------------------------------------------------------------------*/
#ifdef USE_SNMPTRAPD
void  nm_trap_open(const char *name, int port) {
  struct sockaddr_in saddr;
#ifdef HAVE_GETSERVBYNAME
  struct servent *se;
#endif
  /* Socket ja' esta' aberto ? */
  if (nm_trap_sock >= 0)
    return ;

#ifdef HAVE_GETSERVBYNAME
  if (name != NULL) {
    if ((se = getservbyname(name, "udp"))){
      port = ntohs(se->s_port);
    }
  }
  if (port != NM_SNMP_TRAP_PORT && port < 1024){
    perror("snmp: access to port %d denied\n", port);
    exit(1);
  }
#endif  

  if ((nm_trap_sock = socket(AF_INET,SOCK_DGRAM,0)) < 0) {
    perror("snmp: could not create trap socket\n");
    exit(1);
  }

  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(port);
  saddr.sin_addr.s_addr = INADDR_ANY;

  if (bind(nm_trap_sock, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
    perror("snmp: unable to bind trap socket");
    exit(1);
  }
  return;
}

#else
void nm_trap_open(char *straps, int port) {
#ifndef WIN32
  int slen;
  struct sockaddr_un saddr;

  /* Socket ja' esta' aberto ? */
  if (nm_trap_sock >= 0)
    return;

  /* Ambientes UNIX : abrir socket com daemon straps */

  if ((nm_trap_sock = socket(AF_UNIX,SOCK_STREAM,0)) < 0) {
    fprintf(stderr,"snmp: could not create straps socket\n");
    return;
  }

  memset((char *) &saddr, 0, sizeof(saddr));
  saddr.sun_family = AF_UNIX;
  sprintf(saddr.sun_path, "%s-%d", straps_path, port);
  slen = sizeof(saddr) - sizeof(saddr.sun_path) + strlen(saddr.sun_path);

  /* Tenta a conexao com o daemon */
  if (connect(nm_trap_sock,(struct sockaddr *) &saddr, slen) < 0) {
    int retries;
    int pid = -1;

    /* Se nao consegui conexao, tenta startar o daemon */

#ifdef VFORK

    pid = vfork();
#else

    pid = fork();
#endif

    if (pid == 0) {
      int fd;
      
      /* Este processo (filho) vai startar o daemon */
      /* (antes fecha todos os fds, so' deixa stderr) */
      for (fd = 0; fd < _NFILE ; fd++)
        if (fd != STDERR_FILENO )
          close(fd);

      argv[0] = straps;
      sprintf(straps_port, "%d", port);
      argv[1] = straps_port;
      argv[2] = NULL;
      execvp(argv[0],&argv[0]);

      /* Nao deveria passar aqui */
      fprintf(stderr,"snmp: could not execute %s\n",straps);
      _exit(3);
    }
    if (pid == -1) {
      fprintf(stderr,"snmp: could not fork process for %s\n",straps);
      close(nm_trap_sock);
      nm_trap_sock = -1;
      return;
    }

    /* Tenta fazer a conexao agora, em 5 tentativas */
    for (retries = 5; retries; retries--) {
      sleep(1);
      if (connect(nm_trap_sock,(struct sockaddr *) &saddr, slen) >= 0)
        break;
    }
    if (retries == 0) {
      fprintf(stderr,"snmp: could not connect straps socket\n");
      close(nm_trap_sock);
      nm_trap_sock = -1;
      return;
    }
  }
#endif /* WIN32 */
}

#endif /* USE_SNMPTRAPD */
/*-----------------------------------------------------------------------------
 * nm_trap_close
 *
 * Close the trap socket.
 *----------------------------------------------------------------------------*/
void nm_trap_close(void) {
  if (nm_trap_sock != -1)
    close(nm_trap_sock);
  nm_trap_sock = -1;
}

/*-----------------------------------------------------------------------------
 * nm_trap_event
 *
 * Handle Trap event.
 *----------------------------------------------------------------------------*/
#ifndef USE_SNMPTRAPD
static int nm_trap_read(int fd, char *buf, int len) {
  int rc;
  while ((rc = read(fd,buf,len)) < 0 && (errno == EINTR || errno == EAGAIN))
    continue;
  return rc;
}
int nm_trap_event(u_char *packet, int *length, struct sockaddr_in *from) {
  fd_set fdset;
  struct timeval timeout, *tvp;
  int pktlen;

  if (nm_trap_sock == -1) /* socket pode ter sido fechado por erro */
    return 0;

  /* Verifica presenca de pacote recebido no socket trap */
  FD_ZERO(&fdset);
  FD_SET(nm_trap_sock,&fdset);
  tvp = &timeout;
  timerclear(tvp);
  if (select(nm_trap_sock+1,&fdset,0,0,tvp) <= 0)
    return 0;

  /* No caso de uso do straps, o cabecalho inserido pelo daemon sera' tratado */
  /*  (sem daemon, fazer *length = recvfrom(nm_trap_sock,packet,*length,
  0, (struct sockaddr *) from,&fromlength) */

  if (nm_trap_read(nm_trap_sock, (char *) &from->sin_addr.s_addr,4) != 4)
    goto trap_ErrorExit;
  if (nm_trap_read(nm_trap_sock, (char *) &from->sin_port,2) != 2)
    goto trap_ErrorExit;
  from->sin_family = AF_INET;

  if (nm_trap_read(nm_trap_sock, (char *) &pktlen,4) != 4)
    goto trap_ErrorExit;

  /* So' pode ler ate' o tamanho maximo de um pacote (PACKET_LENGTH) */
  if (pktlen <= *length) {
    if (nm_trap_read(nm_trap_sock, (char *)packet,pktlen) != pktlen)
      goto trap_ErrorExit;
    *length = pktlen;
  } else {
    char c;
    if (nm_trap_read(nm_trap_sock, (char *)packet,*length) != *length)
      goto trap_ErrorExit;
    while (pktlen > *length) {
      if (nm_trap_read(nm_trap_sock, &c, 1) != 1)
        goto trap_ErrorExit;
      pktlen--;
    }
  }

  return 1;

  /* Saida deselegante .... */

trap_ErrorExit:
  nm_trap_close();
  fprintf(stderr,"snmp: error reading trap socket (closed now)\n");
  return 0;
}

#else /* USE_SNMPTRAPD */

int nm_trap_event(char *buf, int buflen)
{
  fd_set fdset;
  struct timeval timeout, *tvp;
  int rxlen = 0;

  /* Are we prepared ? */
  if (nm_trap_sock == -1)
    return 0;
  
  /* Check whether have an event */
  FD_ZERO(&fdset);
  FD_SET(nm_trap_sock,&fdset);
  tvp = &timeout;
  timerclear(tvp);
  
  if (select(nm_trap_sock+1,&fdset,0,0,tvp) <= 0)
    /* Nothing */
    return 0;
  /* 
   * Read the contents of the notifications from snmptrapd 
   * 1. sender name
   * 2. sender ip address
   * 3. sysUpTime
   * 4. snmpTrapOID
   * 5. any number of varbinds
   */
  rxlen = read(nm_trap_sock, buf, buflen);
  buf[rxlen] = '\0';
  return rxlen;
}
#endif
