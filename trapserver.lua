local snmp = require "snmp"
local mib = snmp.mib
require "stdlib"
local logging = require "logging.console"

local log = logging.console("%message")
log:setLevel("DEBUG")
local info = function(fmt, ...) log:info(string.format(fmt.."\n", unpack(arg))) end
local debug = function(fmt, ...) log:debug(string.format(fmt.."\n", unpack(arg))) end

info("Initialising SNMP")
if snmp.gettrapd() == "straps" then
  local err = snmp.inittrap("straps")
  assert(not err, err)
else
  info("Support for `%s' has been selected", snmp.gettrapd())
end

local function inform_cb(vlist, ip, session)
  debug("  DEFAULT INFORM CALLBACK: inform sent by : "..ip)
  for _,vb in ipairs(vlist) do
    debug("  %s", snmp.sprintvar(vb))
  end
  inform_done = true
end
local function trap_cb(vlist, ip, host, session)
  debug("  DEFAULT TRAP CALLBACK: trap sent by :%s (%s)", host, ip)
  for _,vb in ipairs(vlist) do
    debug("  %s", session.sprintvar(vb))
  end
  trap_done = true
end


local sess, err = snmp.open{
  community = "private", 
  peer = "localhost",
  version = snmp.SNMPv2C,
  callback = test_cb,
  inform = inform_cb,
  trap = trap_cb
}

--os.execute("snmpinform -v 2c -c public localhost 3 0 sysName.0 s 'hello'")
--while true do
--  err = snmp.event()
--end
err = snmp.loop()
print(err)
assert(not err, err)