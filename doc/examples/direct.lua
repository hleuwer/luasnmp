local snmp = require "snmp"
local sys = io.popen("uname"):read()

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
for k,v in pairs(itab) do print(k,v) end

-- Counts the number of objects in mib-2.
local tcp = hub1["tcp"]
sum = 0
for _,v in pairs(tcp) do
  sum = sum + 1
end
print("Number of entries in 'tcp': " .. sum)
