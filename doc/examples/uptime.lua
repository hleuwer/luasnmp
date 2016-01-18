local snmp = require "snmp"

hub1 = assert(snmp.open{peer = "obelix"})

vb = assert(hub1:get("sysUpTime.0"))
print(vb)

time = snmp.uptimeV2S(vb.value)
ticks = snmp.uptimeS2V(time)

print(time)
table.foreach(ticks, print)
