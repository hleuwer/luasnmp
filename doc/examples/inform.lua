require "snmp"

hub1 = assert(snmp.open{peer = "localhost"})
hub1trap = hub1:clone{port = 162}

local vlist = assert(hub1:get{"sysContact.0", "sysUpTime.0"})
local result, err = hub1trap:inform("sysName.0", vlist)
table.foreach(result, function(k,v) print(v) end)
