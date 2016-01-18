#! /usr/local/bin/lua50
print()
print("gcinfo - initial:", gcinfo())
local snmp = require "snmp"
print("gcinfo - snmp   :", gcinfo())
local socket = require "socket"
print("gcinfo - socket :", gcinfo())

local sess, err = snmp.open{
  peer = "localhost", version = snmp.SNMPv2c, community="public"
}
print("gcinfo - session:", gcinfo())

function perf_get(sess, n, obj)
  local obj = obj or "ifSpeed.1"
  local n = n or 1e3
  for i=1,n do
    local vb,err = sess:get(obj)
  end
end

function perf_getobj(sess, n, obj)
  local obj = obj or "ifSpeed.1"
  local n = n or 1e3
  for i = 1, n do
    local v = sess[obj]
  end
end

function perf_shell(n, obj)
  local obj = obj or "ifSpeed.1"
  local n = n or 1e3
  local cmd = "bash -c 'for ((i="..n..";i--;));do snmpget -v 2c -c public localhost "..obj.." > /dev/null; done'"
  print(cmd)
  os.execute(cmd)
end

function perf_shell2(n, obj)
  local obj = obj or "ifSpeed.1"
  local n = n or 1e3
  local cmd = ""
  for i = 1,n do
    cmd = cmd .. "snmpget -v 2c -c public localhost "..obj.." > /dev/null\n"
  end
  os.execute(cmd)
end

if arg[1] == "-o" then
  perf_getobj(sess, tonumber(arg[2]), arg[3])

elseif arg[1] == "-s1" then
  perf_shell(tonumber(arg[2]), arg[3])

elseif arg[1] == "-s2" then
  perf_shell2(tonumber(arg[2]), arg[3])

else
  perf_get(sess, tonumber(arg[2]), arg[3])
end
