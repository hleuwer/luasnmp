local snmp = require "snmp"

-- Let's have a local reference to this function
local spairs = snmp.spairs

-- Open the session
local hub, err = assert(snmp.open{peer="localhost"})

-- Get a table or part of a table
local ifDescr = hub.ifDescr

-- Print using standard iterator
print("Using standard iterator:")
for k,v in pairs(ifDescr) do
  print(string.format("%s = %s", k, v))
end

-- Print using sorting iterator
print("Using sorting iterator:")
for k,v in spairs(ifDescr) do
  print(string.format("%s = %s", k, v))
end