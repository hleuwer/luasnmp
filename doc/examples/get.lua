require "snmp"

local done = 2

function default_cb(vb, status, index, reqid, session, magic)
  if magic == "local" then
    print("Callback: REQUEST SPECIFIC")
  else
    print("Callback: SESSION DEFAULT")
  end
  print(string.format("  status=%s index=%s reqid=%s magic=%s",
		      status or "nil", index or 0, reqid, magic or "nil"))
  print(string.format("  OID=%s type=%s value=%s",
		      vb.oid, vb.type, vb.value))
  done = done - 1
  session:close()
end


--
-- Trap callback function.
--
local function trap_cb(vlist, ip, host, session)
end
 
--
-- Open session.
--
hub1, err = snmp.open{
  peer = "obelix", 
  community = "private", 
  trap = trap_cb,
  callback = default_cb,
}
assert(hub1, err)

--
-- Clone a session
--
hub2 = assert(snmp.open{peer=hub1.peer, community=hub1.community, callback=hub1.callback})

--
-- Synchronous request
--
local vlist, err, index = snmp.get(hub1, {"sysName.0","sysContact.0"}) 
if not err then 
 print(string.format("Contact for %s : %s", 
                     vlist[1].value, vlist[2].value)) 
else 
  if index then 
    print(string.format("Error : %s in index %d", err, index)) 
  else 
    print(string.format("Error : %s", err)) 
  end 
end

--
-- Asynchronous request on hub1
--
reqid, err = snmp.asynch_get(hub1, "sysContact.0", default_cb, "local")
assert(reqid, err)
print(string.format("reqid = %d", reqid))

--
-- Asynchronous request on hub2
--
reqid, err = snmp.asynch_get(hub2, "sysName.0", nil, "default")
assert(reqid, err)
print(string.format("reqid = %d", reqid))

--
-- Loop for events and callback completion
--
while done > 0 do
  snmp.event()
end

