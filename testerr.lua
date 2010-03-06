local snmp = require "snmp"
require "logging.console"

----------------------------------------------------------------------
-- Logging
----------------------------------------------------------------------
local loglevel = string.upper(arg[1] or "INFO")
local log = logging.console("%message")
log:setLevel(loglevel)
local info = function(fmt, ...) log:info(string.format(fmt.."\n", unpack(arg))) end
local debug = function(fmt, ...) log:debug(string.format(fmt.."\n", unpack(arg))) end


local sessparam = {
  name = "sessv3",
  version = snmp.SNMPv3,
  peer = "localhost",
  user = USER,
  authPassphrase = PASSPHRASE,
  privPassphrase = PASSPHRASE,
  securityLevel = seclevel,
  authType = "MD5",
  privType = "DES",
  --    context = nil,
  --    authid = nil,
  --    contextid = nil,
  --    engboots = nil,
  --    engtime = nil,
  
  -- Callbacks
  callback = nil,
  inform = inform_cb,
  trap = trap_cb
}

local function get_errcode(err)
  for k,v in pairs(snmp.errtb) do
    if v == err then
      return k
    end
  end
  return nil
end

local function get_errname(err)
  for k,v in pairs(snmp) do
--    print("#", k, v, snmp[k])
    if v == err then
      return k
    end
  end
  return nil
end

local function test_sess_err(key, val)
  local param = {}
  for k,v in pairs(sessparam) do
    param[k] = v
  end
  param[key] = val
  local sess, err = snmp.open(param)
  if err then
    local errcode = get_errcode(err)
    local errname = get_errname(errcode)
    debug(" [%s=%s] %s", tostring(errname), tostring(errcode), tostring(err))
    return nil
  else
    debug(" session created")
    return sess
  end
end

local terr= test_sess_err
assert(not terr("version", "hello"))
assert(not terr("port", "hello"))
assert(not terr("timeout", -10))
assert(not terr("retries", -5))
assert(not terr("peer", 17))
assert(not terr("callback", "should be function"))
assert(not terr("trap", "should be function"))
assert(not terr("inform", "should be function"))
print("I should complete this some time ...")