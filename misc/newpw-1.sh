snmpget -v3 -u ronja -A ronja2006 localhost sysContact.0
snmpusm -v 3 -u leuwer -A leuwer2006 -Ca localhost passwd ronja2006 mydog2006 ronja
snmpget -v3 -u ronja -A mydog2006 localhost sysContact.0
snmpusm -v 3 -u leuwer -A leuwer2006 -Ca localhost passwd mydog2006 ronja2006 ronja
snmpget -v3 -u ronja -A ronja2006 localhost sysContact.0
