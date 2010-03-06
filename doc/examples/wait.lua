local snmp = require "snmp"

function func_cb(vb, status, index, reqid, session, magic)
  if magic == "goofy" then
    print("Callback: from goofy")
  else
    print("Callback: from localhost")
  end
  print(vb)
end

hub1 = assert(snmp.open{peer = "goofy"})
hub2 = assert(hub1:clone{peer = "localhost"})

local reqid1 = hub1:asynch_get("sysContact.0", func_cb, "goofy")
local reqid2 = hub2:asynch_get("sysContact.0", func_cb, "localhost")
local reqid2 = hub2:asynch_get("sysName.0", func_cb, "localhost")

print("Waiting for hub1 ...")
hub1:wait()
print("Waiting for hub2 ...")
hub2:wait()
