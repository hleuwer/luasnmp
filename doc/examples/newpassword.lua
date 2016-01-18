local snmp = require "snmp"

-- User who's password to change
local user = "ronja"

-- Old an new passwords
local oldpw = "ronja2006"
local newpw = "mydog2006"

-- 
local check = snmp.check

--
-- Create a work session which we use to change the password back
--
local sess, err = snmp.open{
  peer = "localhost",
  version = snmp.SNMPv3,
  user = "leuwer",
  password = "leuwer2006"
}

--
-- Create a "local" session using OLDPW
--
local sesslocal = check(
   snmp.open{
      peer = "localhost",
      version = snmp.SNMPv3,
      user = user,
      password = oldpw
   })

--
-- Change password implicit using the user's session.
--
local vl = check(sesslocal:newpassword(oldpw, newpw, "a"))
for _,v in ipairs(vl) do print(v) end

-- Close the old session
check(sesslocal:close())

--
-- Reopen the user session using the new password
--
local sessnew = check(
   snmp.open{
      peer = "localhost",
      version = snmp.SNMPv3,
      user = user,
      password = newpw
   })

--
-- Use it ...
--
print(check(sessnew:get("sysContact.0")))

--
-- Close the user session
--
check(sessnew:close())

--
-- Change password back from NEWPW to OLDPW explicitly
-- using the worker session
--
vl = check(sess:newpassword(newpw, oldpw, "a", user))
for _,v in ipairs(vl) do print(v) end

--
-- Close the worker session
--
check(sess:close())
