local snmp = require "snmp"

hub1, err = snmp.open{
  peer = "goofy", 
  community = "private", 
}
assert(hub1, err)

vbIn = {
  {oid = "sysContact.0", value = "root"}, 
  {oid = "sysLocation.0", value="MyHome"}
}
vbOut, err, index = hub1:set(vbIn)
assert(vbOut, err)
print(vbOut[1])
print(vbOut[2])
