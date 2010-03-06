local snmp = require "snmp"
local mib = snmp.mib

local function printf(fmt, ...)
  print(string.format(fmt, unpack(arg)))
end

local function sleep(n)
  os.execute("sleep "..tostring(n))
end

local user = "ronja"
local oldpw = "ronja2006"
local newpw = "mydog2005"
local T = 0
local clonenew = true
local cloneold = false
local reuseold = false
local reopenold = true
require "stdlib"

for i=1,20 do

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
    user = user,
    password = oldpw
  }
  assert(sessold, err)
  
  --assert(sessnew, err)
  
  printf("\n===== Using MASTER session")
  local vb, err = sess:get("sysContact.0")
  assert(vb, err)
  printf(tostring(vb))
  
  printf("\n===== Using OLD session")
  vb, err = sessold:get("sysContact.0")
  assert(vb, err)
  printf(tostring(vb))
  
  printf("\n===== Changing password to NEW")
  local vl, err = sess:newpassword(oldpw, newpw, "a", user)
  assert(vl, err)
  for _,v in ipairs(vl) do printf(tostring(v)) end
  printf("password successfully changed for user %s.", user)

  sleep(T)
  
  local sessnew
  if clonenew then
    sessnew, err = sess:clone{user=user, password = newpw}
  else
    sessnew, err = snmp.open{
      peer = "localhost",
      version = snmp.SNMPv3,
      user = user,
      password = newpw
    }
  end
  assert(sessnew, err)
  local x = sessnew:details()
  
  printf("\n===== Using NEW session")
  vb, err = sessnew:get("sysContact.0")
  assert(vb, err)
  printf(tostring(vb))
  
  printf("\n===== Changing password back to OLD")
  vl, err = sess:newpassword(newpw, oldpw, "a", user)
  assert(vl, err)
  for _,v in ipairs(vl) do print(tostring(v)) end
  printf("password successfully changed back for user %s.", user)
  
  sleep(T)
  
  local sessold2
  if reuseold == true then
    sessold2 = sessold
  else
    if cloneold then
      printf("\n===== Clone OLD session")
      sessold2, err = sessold:clone{password = oldpw}
    else
      if reopenold then
	printf("\n===== Reopen OLD session")
	sessold2, err = snmp.open{
	  peer = "localhost",
	  version = snmp.SNMPv3,
	  user = user,
	  password = oldpw
	}
      end
    end
  end
  assert(sessold2, err)
  
  printf("\n===== Using OLD session again")
  vb, err = sessold2:get("sysContact.0")
  assert(vb, err)
  printf(tostring(vb))
  assert(not sess:close(),"sess")
  assert(not sessold:close(), "sessold")
  assert(not sessnew:close(), "sessnew")
  assert(not sessold2:close(), "sessold2")
end  
