local snmp = require "snmp"

hub1 = assert(snmp.open{peer = "goofy"})

vb = assert(hub1:get("sysContact.0"))
print("OUTPUT of 'sprintvar':")
print(vb)
print(snmp.sprintvar(vb))
print(hub1.sprintvar(vb))
print(snmp.sprintvar2(vb))
print()
print("OUTPUT of 'sprintval':")
print(snmp.sprintval(vb))
print(snmp.sprintval2(vb))
print()
print("OUTPUT of 'sprinttype':")
print(snmp.sprinttype(vb))
print(snmp.mib.typename(vb))
