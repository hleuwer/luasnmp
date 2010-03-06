#! /usr/local/bin/lua50

local snmp = require "snmp"
local mib = snmp.mib

-- Open SNMP session
local hub, err  = assert(snmp.open{peer = arg[1] or "localhost"})

-- Retrieve symbolic values for ifAdminStatus
local vb, err = hub:get("laLoadFloat.1")
print(vb)
hub:close()