local snmp = require "snmp"

hub1 = assert(snmp.open{peer = "localhost", community = "private"})

-- Sets an re-stores sysContact.0
local oldval = hub1.sysContact_0
print("sysContact.0 = " .. hub1.sysContact_0)

hub1.sysContact_0 = "admin"
print("sysContact.0 = " .. hub1["sysContact.0"])

hub1["sysContact.0"] = oldval
print("sysContact.0 = " .. hub1.sysContact_0)

-- Shows the list of interface names
itab = hub1.ifName
table.foreach(itab, print)

-- Counts the number of objects in mib-2.
local mib2 = hub1["mib-2"]
sum = 0
for _,v in pairs(mib2) do
  sum = sum + 1
end
print("Number of entries in 'mib-2': " .. sum)
