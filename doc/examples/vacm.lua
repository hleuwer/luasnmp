local snmp = require "snmp"
local mib = snmp.mib

-- We will use this frequently - so let's have a local ref
local check = snmp.check

--
-- Open a working session
--
local sess, err = check(snmp.open{
  peer = "localhost",
  version = snmp.SNMPv3,
  user = "leuwer",
  password = "leuwer2006",
			})
--
-- Create a user to give access to.
--
local vl = check(sess:createuser("olivia", "ronja"))

--
-- The new user typically needs a new password. 
--
vl = check(sess:newpassword("ronja2006", "gonzo2006", "a", "olivia"))

--
-- Create security name to group mapping.
--
vl, err = sess:createsectogroup("usm", "olivia", "rwgroup")
if err then
  -- 
  -- An error occurred: cleanup and delete the above new user here.
  --
  vl = check(sess:deleteuser("olivia"))
  sess:close()
  os.exit(1)
end

--
-- Create a new view 'interfaces'
--
vl = check(sess:createview("interfaces", mib.oid("ifTable"), "80", "include"))

--
-- Create a new access entry for the new group.
--
vl = check(sess:createaccess("rwgroup", "usm", "authNoPriv", "exact", 
			     "interfaces", "interfaces", "_none_"))

--
-- Let's have a look at all this stuff
--
table.foreach(sess:walk("vacmAccessTable"), print)

-- Finished: now we could test gos and nogos in the access.
-- Cleanup all newly created stuff.
--
vl = check(sess:deleteaccess("rwgroup", "usm", "authNoPriv"))
vl = check(sess:deleteview("interfaces", mib.oid("ifTable")))
vl = check(sess:deletesectogroup("usm", "olivia"))
vl = check(sess:deleteuser("olivia"))
sess:close()
