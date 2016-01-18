local snmp = require "snmp"
local mib = snmp.mib

-- We will use this frequently
local check = snmp.check

-- Lets define a convenient print function
function printf(fmt, ...)
  print(string.format(fmt, unpack(arg)))
end

-- User to create
local user = "popey"

-- User to clone from
local clonefromuser = "ronja"

-- Open a working session
local sess, err = snmp.open{
  peer = "localhost",
  version = snmp.SNMPv3,
  user = "leuwer",
  password = "leuwer2006"
}
check(sess, err)

-- Create the user 'popey'
local vl, err = check(sess:createuser(user, clonefromuser))
for _,v in ipairs(vl) do print(v) end

-- Read and print popey's usmUserStatus
print(check(sess:get(mib.oid("usmUserStatus") .. snmp.instance(sess.contextEngineID, user))))

-- Delete the user again
local vb, err = check(sess:deleteuser(user))

-- Read and print popey's usmUserStatus
print(check(sess:get(mib.oid("usmUserStatus") .. mib.instance(sess.contextEngineID, user))))

-- Close the working session
check(sess:close())
