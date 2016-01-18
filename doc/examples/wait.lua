local snmp = require "snmp"

function func_cb(vb, status, index, reqid, session, magic)
  if magic == "obelix" then
    print("Callback: from obelix")
  else
    print("Callback: from localhost")
  end
  print(vb)
end

hub1 = assert(snmp.open{peer = "obelix"})
hub2 = assert(snmp.open{peer = "localhost"})

local reqid1 = hub1:asynch_get("sysContact.0", func_cb, "obelix")
local reqid2 = hub2:asynch_get("sysContact.0", func_cb, "localhost")
local reqid2 = hub2:asynch_get("sysName.0", func_cb, "localhost")

print("Waiting for hub1 ...")
hub1:wait()
print("Waiting for hub2 ...")
hub2:wait()
