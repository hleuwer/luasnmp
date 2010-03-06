local snmp = require "snmp"

-- Open the session
local hub, err = assert(snmp.open{peer="localhost"})

-- Get a table or part of a table
local ifDescr = hub.ifDescr

local keys = snmp.getkeys(ifDescr)

-- Print using standard iterator
print("Using standard iterator:")
for k,v in pairs(ifDescr) do
  print(string.format("%s = %s", k, v))
end

-- Print using sorting iterator
print("Using sorting iterator:")
for i,key in ipairs(keys) do
  print(string.format("%s = %s", key, ifDescr[key]))
end