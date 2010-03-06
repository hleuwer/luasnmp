#!/usr/bin/env sh
for i in $*
  do
  case $1 in
      install)
	  echo "Installing snmpd"
	  cygrunsrv -I snmpd -p /usr/local/sbin/snmpd.exe \
	      -e MIBDIRS="/usr/local/share/snmp/mibs" \
	      -a "-f -Lf /var/log/snmpd.log" \
	      -f "SNMP Agent (cygwin)" \
	      -t manual
	  echo "Installing snmptrapd"
	  cygrunsrv -I snmptrapd -p /usr/local/sbin/snmptrapd.exe \
	      -e MIBDIRS="/usr/local/share/snmp/mibs" \
	      -e LUA_PATH="/usr/local/share/lua/5.1/?.lua" \
	      -e LUA_INIT="require 'luarocks.require'" \
	      -e LUA_CPATH="/usr/local/lib/lua/5.1/?.dll" \
	      -a "-d -f -Lf /var/log/snmptrapd.log" \
	      -f "SNMP TrapDaemon (cygwin)" \
	      -t manual
	  ;;
      start)
	  echo "Starting snmpd"
	  cygrunsrv -S snmpd
	  echo "Starting snmptrapd"
	  cygrunsrv -S snmptrapd
	  ;;
      restart)
	  echo "Stopping snmpd"
	  cygrunsrv -E snmpd
	  echo "Stopping snmptrapd"
	  cygrunsrv -E snmptrapd 
	  echo "Restarting snmpd"
	  cygrunsrv -S snmpd 
	  echo "Restarting snmptrapd"
	  cygrunsrv -S snmptrapd 
	  ;;
      stop)
	  echo "Stopping snmpd"
	  cygrunsrv -E snmpd
	  echo "Stopping snmptrapd"
	  cygrunsrv -E snmptrapd 
	  ;;
      remove)
	  echo "Removing snmpd"
	  cygrunsrv -R snmpd
	  echo "Removing snmptrapd"
	  cygrunsrv -R snmptrapd 
	  ;;
      query)
	  echo "Query snmpd and snmptrapd"
	  cygrunsrv -Q snmpd
	  cygrunsrv -Q snmptrapd 
	  ;;
      help)
	  echo "usage snmpdwin32.sh help | install | start | restart | stop | remove | query"
	  echo "      You can also give more commands at once, e.g."
	  echo "         snmpdwin32.sh install start"
	  ;;
  esac
  shift 
done