local snmp = require "snmp"
local mib = snmp.mib


local sess = snmp.open{
  peer = "localhost",
  version = snmp.SNMPv3,
  user = "leuwer",
  password = "leuwer2006"
}
local protos = {
  snmp.usmProtocol.HMACMD5Auth,
  snmp.usmProtocol.HMACSHA1Auth
}

for hash,oid in pairs(protos) do
  print("hashtype: " .. hash .." "..oid)
  local oldkey, oldlen = assert(snmp.createkey(sess, "leuwer2006", oid))
  local newkey, newlen = assert(snmp.createkey(sess, "herbert2006", oid))
  local chgkey, chglen = assert(snmp.keychange(sess, oldkey, newkey, oid))
  if not chgkey then 
    print("ERROR   : ".. chglen_err .. "\n")
  else
    print("change_key len  : " .. string.len(chgkey))
    io.write("change key      : 0x")
    for i = 1, string.len(chgkey) do
      io.write(string.format("%02X", string.byte(string.sub(chgkey, i,i+1))))
    end
    print("\n")
  end
  if witherr then break end
end