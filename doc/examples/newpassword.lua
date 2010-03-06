local snmp = require "snmp"

-- User who's password to change
local user = "ronja"

-- Old an new passwords
local oldpw = "ronja2006"
local newpw = "mydog2006"

-- 
local check = snmp.check

--
-- Create a work session which we use to change the password
--
local sess, err = snmp.open{
  peer = "goofy",
  version = snmp.SNMPv3,
  user = "leuwer",
  password = "leuwer2006"
}

--
-- Create an "old" session using OLDPW
--
local sessold = check(snmp.open{
  peer = "localhost",
  version = snmp.SNMPv3,
  user = user,
  password = oldpw})

--
-- Change password implicit using the user's session.
--
local vl = check(sessold:newpassword(oldpw, newpw, "a"))
for _,v in ipairs(vl) do print(v) end

--
-- Create a "new" session using NEWPW for the user
--
local sessnew = check(sessold:clone{password = newpw})

--
-- Use the "new" session
--
print(check(sessnew:get("sysContact.0")))

--
-- Change password back from NEWPW to OLDPW explicitly
-- using the worker session
--
vl = check(sess:newpassword(newpw, oldpw, "a", user))
for _,v in ipairs(vl) do print(v) end

--
-- Reopen the old session. This will reuse OLDPW.
--
sessold2 = check(sessold:clone())

--
-- Use the reopened session
--
vb = check(sessold2:get("sysContact.0"))
print(vb)

--
-- Close all sessions created
--
check(sessold:close())
check(sessnew:close())
check(sessold2:close())
check(sess:close())
