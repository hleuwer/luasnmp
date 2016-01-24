local snmp = require "snmp"

local ifNum = 3

hub1 = assert(snmp.open{peer = "obelix"})

ifList, err, index = hub1:getbulk(0, ifNum, {"ifDescr","ifType"})
assert(ifList, err)

local types = snmp.mib.enums("ifType")
i = 1; last=ifNum * 2
while i < last do
  print(ifList[i].value..": "..types[ifList[i+1].value])
  i = i + 2
end
for _,v in ipairs(ifList) do
   print(v)
end
