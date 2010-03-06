#! /usr/local/bin/lua50

local snmp = require "snmp"
local mib = snmp.mib

-- Open SNMP session
local hub, err  = assert(snmp.open{peer = arg[1] or "localhost"})

-- Retrieve symbolic values for ifAdminStatus
local rstatus = mib.enums("ifAdminStatus")
local status = mib.renums("ifAdminStatus")

-- Print just the value
print(rstatus[hub.ifAdminStatus_4])

-- Just print current status value
print(hub:sprintval(hub:get("ifAdminStatus.4")))

-- Set status twice and print each result
local vb, err = assert(hub:set{oid="IF-MIB::ifAdminStatus.4", value=status.down})
print(vb)
local vb, err = assert(hub:set{oid="ifAdminStatus.4", value=status.up})
print(vb)

-- Done.
hub:close()