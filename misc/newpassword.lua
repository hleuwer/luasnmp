local snmp = require "snmp"
local mib = snmp.mib

require "stdlib"

local function printf(fmt, ...)
  print(string.format(fmt, unpack(arg)))
end

local user = "ronja"
local oldpw = "ronja2006"
local newpw = "mydog2006"

local sess, err = snmp.open{
  peer = "localhost",
  version = snmp.SNMPv3,
  user = "leuwer",
  password = "leuwer2006"
}
assert(sess, err)

local sessold, err = snmp.open{
  peer = "localhost",
  version = snmp.SNMPv3,
  user = "ronja",
  password = "ronja2006"
}
assert(sessold, err)

local sessnew, err = sessold:clone{password = "mydog2006"}
assert(sessnew, err)

printf("\n===== Using OLD session")
local vb, err = sessold:get("sysContact.0")
assert(vb, err)
printf(tostring(vb))

printf("\n===== Changing password to NEW")
local vl, err = sess:newpassword(oldpw, newpw, "a", user)
assert(vl, err)
printf("password successfully changed for user %s.", user)


printf("\n===== Using NEW session")
local vb, err = sessnew:get("sysContact.0")
assert(vb, err)
printf(tostring(vb))

printf("\n===== Changing password back to OLD")
local vl, err = sess:newpassword(newpw, oldpw, "a", user)
assert(vl, err)
printf("password successfully changed back for user %s.", user)

local vb, err = sessold:get("sysContact.0")
assert(vb, err)
printf(vb)

sess:close()