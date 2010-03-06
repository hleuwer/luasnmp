local snmp = require "snmp"
local mib = snmp.mib
require "stdlib"

local check = snmp.check

function printf(fmt, ...)
  print(string.format(fmt, unpack(arg)))
end

local user = "popey"
local newpw = "gonzosfriend"
local clonefromuser = "ronja"
local clonefromuserpw = "ronja2006"

local sess, err = snmp.open{
  peer = "goofy",
  version = snmp.SNMPv3,
  user = "leuwer",
  password = "leuwer2006"
}
check(sess, err)

local sessclone, err = snmp.open{
  peer = "goofy",
  version = snmp.SNMPv3,
  user = clonefromuser,
  password = clonefromuserpw
}
check(sessclone)

printf("=== User Status")
local vl, err, errindex = sess:walk("usmUserStatus")
check(vl, err)
for _,v in ipairs(vl) do printf("  %s", tostring(v)) end

printf("=== Creating user %q", user)
local vb, err = sess:createuser(user)
check(vb, err)
print(vb)
local node = mib.oid("usmUserStatus")..snmp.mkindex(sess.contextEngineID, user) 
print(node)
local vb ,err = sess:get(node)
print(pretty(vb), err)
print(vb)
printf("=== User Status")
local vl, err, errindex = sess:walk("usmUserStatus")
check(vl, err)
for _,v in ipairs(vl) do printf("  %s", tostring(v)) end

printf("=== Make user %q a clone from %q", user, clonefromuser)
local vl, err = sess:clonefromuser(user, clonefromuser)
check(vl, err)
for _,v in ipairs(vl) do printf("  %s", tostring(v)) end

printf("=== User Status")
local vl, err, errindex = sess:walk("usmUserStatus")
check(vl, err)
for _,v in ipairs(vl) do printf("  %s", tostring(v)) end

printf("=== Opening a session for user %q", user)
local usersess, err = snmp.open{
  peer = "goofy",
  version = snmp.SNMPv3,
  user = user,
  password = clonefromuserpw
}
check(usersess, err)
local vb, err = sessclone:get("sysContact.0") print(vb)
local vb, err = sess:get("sysContact.0") print(vb)
local vb, err = usersess:get("sysContact.0")
print(pretty(vb))
check(vb and not err, err)
printf("  %s", tostring(vb))

printf("=== Closing the session for user %q", user)
check(not usersess:close())

printf("=== Deleting user %q", user)
local vb, err = sess:deleteuser(user)
check(vb, err)
print(vb)

printf("=== User Status 1")
local vl, err, errindex = sess:walk("usmUserStatus")
check(vl, err)
for _,v in ipairs(vl) do printf("  %s", tostring(v)) end

printf("=== User Status 2")
local vl, err, errindex = sess:walk("usmUserStatus")
check(vl, err)
for _,v in ipairs(vl) do printf("  %s", tostring(v)) end

printf("=== Creating user %q as clone from user %q", user, clonefromuser)
local vl, err = sess:createuser(user, clonefromuser)
check(vl, err)
for _,v in ipairs(vl) do printf("  %s", tostring(v)) end

printf("=== User Status")
local vl, err, errindex = sess:walk("usmUserStatus")
check(vl, err)
for _,v in ipairs(vl) do printf("  %s", tostring(v)) end

printf("=== Opening a session for user %q", user)
local usersess, err = snmp.open{
  peer = "goofy",
  version = snmp.SNMPv3,
  user = user,
  password = clonefromuserpw
}
check(usersess, err)

local vb, err = usersess:get("sysContact.0")
check(vb, err)
printf("  %s", tostring(vb))

printf("=== Closing the session for user %q", user)
check(not usersess:close())

printf("=== Deleting user %q", user)
local vb, err = sess:deleteuser(user)
check(vb, err)
print(vb)

printf("=== User Status")
local vl, err, errindex = sess:walk("usmUserStatus")
check(vl, err)
for _,v in ipairs(vl) do printf("  %s", tostring(v)) end

check(not sess:close())
check(not sessclone:close())
