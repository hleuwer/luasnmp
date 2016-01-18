require "snmp"

hub1 = assert(snmp.open{peer = "obelix"})

vlist = assert(hub1:walk("ifType"))
table.foreach(vlist, function(k,v) print(v) end)
