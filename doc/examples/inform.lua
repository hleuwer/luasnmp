require "snmp"
mib = snmp.mib
require "pl.pretty"
local pretty = pretty.write
local function usage() 
   io.stderr:write("usage: lua inform.lua SNMPVERSION\n")
   os.exit(1)
end
local arg = {select(1, ...)}
if #arg == 0 then
   usage()
end

local hub
if arg[1] == "v2" then
   hub, err = snmp.open{
      peer = "localhost", 
      community="private", 
      port = 162
   }
elseif arg[1] == "v3" then
   hub, err = snmp.open{
        name = "trapsess_sync",
        user = "leuwer",
        password = "leuwer2006",
        engineID = "0102030405",
--        contextID = "0102030405",
        peer = "localhost",
        version = snmp.SNMPv3,
        port = 162
   }
else
   usage()
end
assert(hub, err)
local vb2 = snmp.newvar("sysLocation.0","hello")
print("vb2:", vb2)
print("vb2="..pretty(vb2))
local result, err = assert(hub:inform("sysContact.0", vb2))
print("result="..pretty(result))
--table.foreach(result, function(k,v) print(v) end)
hub:close()
