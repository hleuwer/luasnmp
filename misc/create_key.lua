local snmp = require "snmp"
local mib = snmp.mib
require "stdlib"

local witherr = false

local sess = snmp.open{
  peer = "localhost",
  version = snmp.SNMPv3,
  user = "leuwer",
  password = "leuwer2006",
  community = "private"
}
print(string.format("engineID=%q", sess.contextEngineID))
local t = sess:details()
table.foreach(t, print)
print(string.format("Details: %s %q %d", 
		    type(t), snmp.sprintkey(t.contextEngineID or ""), t.contextEngineIDLen))

local vb, err = sess:get(nil)
assert(vb,err)

local t = sess:details()
table.foreach(t, print)
print(string.format("Details: %s %q %d", 
		    type(t), snmp.sprintkey(t.contextEngineID or ""), t.contextEngineIDLen))
print()
for hash,oid in pairs(snmp.usmProtocol) do
  print("hashtype: " .. hash)
  print("OID     : " .. oid)
  if witherr then oid = nil end
  local key, keylen_err = snmp.createkey(sess, "leuwer2006", oid)
  if not key then 
    print("ERROR   : ".. keylen_err .. "\n")
  else
    print(string.format("keylen : %d",string.len(key)))
    print(string.format("key    : %q", snmp.sprintkey(key)))
    local Lkey, Lkeylen_err = snmp.createlocalkey(sess, key, oid)
    if not Lkey then 
      print("\nERROR   : ".. Lkeylen_err .. "\n")
    else
      print(string.format("1 Lkeylen: %d",string.len(Lkey)))
      print(string.format("1 Lkey   : %q", snmp.sprintkey(Lkey)))
    end
    local Lkey, Lkeylen_err = snmp.createlocalkey(sess, key, oid, t.contextEngineID)
    if not Lkey then 
      print("\nERROR   : ".. Lkeylen_err .. "\n")
    else
      print(string.format("2 Lkeylen: %d",string.len(Lkey)))
      print(string.format("2 Lkey   : %q", snmp.sprintkey(Lkey)))
    end
    print("\n")
  end
  if witherr then break end
end