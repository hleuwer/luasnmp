#! /usr/local/bin/lua50

local snmp = require "snmp"
local mib = snmp.mib

-- Open SNMP session
local hub, err  = assert(snmp.open{peer = arg[1] or "localhost", community="private"})

-- Retrieve symbolic values for ifAdminStatus
local rstatus = mib.enums("ifAdminStatus")
local status = mib.renums("ifAdminStatus")
table.foreach(rstatus, print)
table.foreach(status, print)

-- Print just the value
--print(rstatus[hub.ifAdminStatus_3])

-- Just print current status value
print(hub:sprintval(hub:get("ifAdminStatus.3")))

-- Set status twice and print each result
local vb, err = assert(hub:set{oid="IF-MIB::ifAdminStatus.3", value=status.down})
print(vb)
local vb, err = assert(hub:set{oid="ifAdminStatus.3", value=status.up})
print(vb)

-- Done.
hub:close()
