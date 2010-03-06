#!/usr/bin/env sh
for i in $*
  do
  case $1 in
      start)
	  echo "Starting snmpd" 
	  /usr/local/sbin/snmpd -p /var/log/snmpd.pid -Lf /var/log/snmpd.log
	  echo "Starting snmptrapd"
	  rm -f /var/log/trapd.log
	  /usr/local/sbin/snmptrapd -p /var/log/snmptrapd.pid -d -Lf /var/log/snmptrapd.log
	  ;;
      stop)
	  echo "Stopping snmpd"
	  test -e /var/log/snmpd.pid && kill `cat /var/log/snmpd.pid`
	  echo "Stopping snmptrapd"
	  test -e /var/log/snmptrapd.pid && kill `cat /var/log/snmptrapd.pid`
	  ;;
      restart)
	  $0 stop
	  $0 start
	  ;;
      query)
	  echo "Query snmpd and snmptrapd"
	  echo "snmpd     PID:"`cat /var/log/snmpd.pid`
	  echo "snmptrapd PID:"`cat /var/log/snmptrapd.pid`
	  ;;
      help)
	  echo "usage snmpdwin32.sh help | start | restart | stop | query"
	  echo "      You can also give more commands at once, e.g."
	  echo "         snmpdwin32.sh install start"
	  ;;
  esac
  shift 
done