------------------------------------------------------------------------------
--
-- snmp.lua : SNMP primitives
--
------------------------------------------------------------------------------

local snmp = require "snmp.core"
local mib = snmp.mib

-- Lua version compatibility
local unpack = unpack or table.unpack

if string.find(_VERSION, "5.1") then
   module("snmp", package.seeall)
else
   _ENV = setmetatable(snmp, {
                          __index = _G
   })
end
------------------------------------------------------------------------------
-- Default Exception Handler
------------------------------------------------------------------------------
try = newtry()

------------------------------------------------------------------------------
-- MIB definitions
------------------------------------------------------------------------------
mib.NOACCESS  =  0
mib.READONLY  =  1
mib.READWRITE =  2
mib.WRITEONLY =  3
mib.READCREATE = 4

------------------------------------------------------------------------------
-- Init Mibs and SNMP client
------------------------------------------------------------------------------
mib.init()

------------------------------------------------------------------------------
-- Reverse 
------------------------------------------------------------------------------
function mib.renums(oid)
  local t, err = mib.enums(oid)
  if not t then return nil, err end
  local rv = {}
  for k, v in ipairs(t) do
    rv[v] = k
  end
  return rv
end

------------------------------------------------------------------------------
-- Assemble list of net-snmp config files
------------------------------------------------------------------------------
local function configfiles()
  local dirlist = {
    "/etc/snmp/",
    "/usr/lib/snmp/",
    "/usr/share/snmp/",
    os.getenv("HOME").."/.snmp/"
  }
  local filelist = {
    "snmp.conf",
    "snmp.local.conf",
--    "snmpapp.conf"
  }
  local t = {}
  local confpath = os.getenv("SNMPCONFPATH")
  if confpath then 
    for dir in string.gmatch(confpath, "[^:]+") do
      table.insert(t, dir .. "/snmp.conf")
      table.insert(t, dir .. "/snmp.local.conf")
      table.insert(t, dir .. "/snmpapp.conf")
    end
  else
    for _, dir in ipairs(dirlist) do
      for _, file in ipairs(filelist) do
	table.insert(t, dir .. file)
      end
    end
  end
  return t
end


------------------------------------------------------------------------------
-- Gather SNMP configuration
------------------------------------------------------------------------------
local function read_config()
  local config = {}
  for _, fname in ipairs(configfiles()) do
    local f = io.open(fname, "r") 
    if f then 
      for line in f:lines() do
	tok, val = string.gsub(line, "^%s*(#*)%s*(%w+)%s+([^%s#]*)",
			       function(comment1, tok, val)
				 if comment1 ~= "#" then
-- Uncomment to see which token read from which file.
--				   print(string.format("config-read: %s = %s from %s",
--						       tok, val, fname))
				   config[tok] = val
				 end
			       end)
      end
      f:close()
    end
  end
  return config
end

config = read_config()
local tokens = {
  "pathStrap",
  "trapdPort"
}

------------------------------------------------------------------------------
-- A metatable for variable bindings.
------------------------------------------------------------------------------
__vbindmetatable = {
  __tostring = sprint_variable,
  __eq = function(vb1, vb2) return vb1.value == vb2.value end,
  __le = function(vb1, vb2) return vb1.value <= vb2.value end,
  __lt = function(vb1, vb2) return vb1.value < vb2.value end,
  __concat = function(vb1, vb2) 
	       local vb = {}
	       if vb1.oid and vb2.oid then return {vb1, vb2} end
	       if not vb1.oid then
		 for _, v in ipairs(vb1) do table.insert(vb, v) end
		 if vb2.oid then
		   table.insert(vb, vb2)
		 else
		   for _, v in ipairs(vb2) do table.insert(vb, v) end
		 end
	       else
		 table.insert(vb, vb1)
		 for _, v in ipairs(vb2) do table.insert(vb, v) end
	       end
	       return vb
	     end
}

------------------------------------------------------------------------------
-- Init general things and config tokens
------------------------------------------------------------------------------
assert(not init(tokens, function(token, line)
			end))

------------------------------------------------------------------------------
-- Init Traps handler. 
-- 1. LUASNMP_STRAPS is set: use straps
-- 2. LUASNMP_TRAPDPORT is set: use LUASNMP_TRAPDPORT
-- 3. trapdPort in snmp.conf is set: use configuration value
-- 4. Use port 6000
------------------------------------------------------------------------------
local trapdport = tonumber(os.getenv("LUASNMP_TRAPDPORT") or 
			      config.trapdPort) or 6000
if trapdport then
   inittrap(trapdport)
end


------------------------------------------------------------------------------
-- Session configuration parameters
------------------------------------------------------------------------------
SNMPv1 = 0
SNMPv2C = 1
SNMPv2c = 1
SNMPv2u = 2
SNMPv3 = 3

local NOAUTH = 1
local AUTHNOPRIV = 2
local AUTHPRIV = 3
local seclevels = {
  ["noAuthNoPriv"] = NOAUTH, 
  ["authNoPriv"] = AUTHNOPRIV, 
  ["authPriv"] = AUTHPRIV
}
local secmodels = {
  ["SNMPv1"] = 1,
  ["SNMPv2c"] = 2,
  ["USM"] = 3
}
------------------------------------------------------------------------------
-- SNMPv3 transform OIDs
-- Giving them here explicitly avoids the necessity to load the MIBs.
------------------------------------------------------------------------------
usmProtocol = {
  NoAuth       = "1.3.6.1.6.3.10.1.1.1",
  HMACMD5Auth  = "1.3.6.1.6.3.10.1.1.2",
  HMACSHA1Auth = "1.3.6.1.6.3.10.1.1.3",
  NoPriv       = "1.3.6.1.6.3.10.1.2.1",
  DESPriv      = "1.3.6.1.6.3.10.1.2.2",
  AESPriv      = "1.3.6.1.6.3.10.1.2.4"
}

keyOid = {
  auth = "1.3.6.1.6.3.15.1.2.2.1.6",
  ownAuth = "1.3.6.1.6.3.15.1.2.2.1.7",
  priv = "1.3.6.1.6.3.15.1.2.2.1.9",
  ownPriv = "1.3.6.1.6.3.15.1.2.2.1.10"
}

usmOid = {
  userStatus =      "1.3.6.1.6.3.15.1.2.2.1.13",
  userSecurityName = "1.3.6.1.6.3.15.1.2.2.1.3",
  userCloneFrom =   "1.3.6.1.6.3.15.1.2.2.1.4"
}

vacmOid = {
  groupName = "1.3.6.1.6.3.16.1.2.1.3",
  sec2GroupStorageType = "1.3.6.1.6.3.16.1.2.1.4", 
  sec2GroupStatus = "1.3.6.1.6.3.16.1.2.1.5", 
  accessContextMatch = "1.3.6.1.6.3.16.1.4.1.4", 
  accessReadViewName = "1.3.6.1.6.3.16.1.4.1.5", 
  accessWriteViewName = "1.3.6.1.6.3.16.1.4.1.6", 
  accessNotifyViewName = "1.3.6.1.6.3.16.1.4.1.7", 
  accessStorageType = "1.3.6.1.6.3.16.1.4.1.8", 
  accessStatus = "1.3.6.1.6.3.16.1.4.1.9", 
  viewTreeFamilyMask = "1.3.6.1.6.3.16.1.5.2.1.3", 
  viewTreeFamilyType = "1.3.6.1.6.3.16.1.5.2.1.4",
  viewTreeFamilyStorageType = "1.3.6.1.6.3.16.1.5.2.1.5",
  viewTreeFamilyStatus = "1.3.6.1.6.3.16.1.5.2.1.6"
}
rowStatus = {
  active = 1,
  notInService = 2,
  notReady = 3,
  createAndGo = 4,
  createAndWait = 5,
  destroy = 6,
}
------------------------------------------------------------------------------
-- Error Codes
------------------------------------------------------------------------------
NOERROR		        =  0
TOOBIG		        =  1
NOSUCHNAME	        =  2
BADVALUE	        =  3
READONLY	        =  4
GENERR		        =  5
NOACCESS	        =  6
WRONGTYPE	        =  7
WRONGLENGTH	        =  8
WRONGENCODING	        =  9
WRONGVALUE	        = 10
NOCREATION	        = 11
INCONSISTENTVALUE	= 12
RESOURCEUNAVAILABLE	= 13
COMMITFAILED		= 14
UNDOFAILED		= 15
AUTHORIZATIONERROR	= 16
NOTWRITABLE		= 17
INCONSISTENTNAME	= 18

BADVERSION	= 101
BADCOMMUNITY	= 102
BADTIME		= 103
BADRETRIES	= 104
BADPEER		= 105
BADPORT		= 106
BADCALLBACK	= 107
BADTRAP		= 108
BADINFO		= 109
INVINFO		= 110
BADPRINTVAR     = 111
BADPRINTVAL     = 112
BADUSER         = 113
BADSECLEVEL     = 114
BADPASSPHRASE   = 115
BADPRIVPASSPHRASE = 116
BADENGBOOTS     = 117
BADENGTIME      = 118
BADINCL         = 119
BADSESSION	= 120
BADTYPE		= 121
BADNAME		= NOSUCHNAME
BADNR		= 123
BADMR		= 124
INVINFOREQ	= 125
BADTRAPOID	= 126
TIMEOUT		= 190
INTERR		= 191
BADARG          = 192
BADOID          = 193
BADENGPROBE     = 194         
BADSECMODEL     = 195      
BADSECNAME      = 196   
BADGROUPNAME    = 197

------------------------------------------------------------------------------
-- Error Messages
------------------------------------------------------------------------------
errtb={}
errtb[0] = "snmp: no error"
errtb[1] = "snmp: too big"
errtb[2] = "snmp: no such name"
errtb[3] = "snmp: bad value"
errtb[4] = "snmp: read only"
errtb[5] = "snmp: generic error"
errtb[6] = "snmp: no access"
errtb[7] = "snmp: wrong type"
errtb[8] = "snmp: wrong length"
errtb[9] = "snmp: wrong encoding"
errtb[10] = "snmp: wrong value"
errtb[11] = "snmp: no creation"
errtb[12] = "snmp: inconsistent value"
errtb[13] = "snmp: resource unavailable"
errtb[14] = "snmp: commit failed"
errtb[15] = "snmp: undo failed"
errtb[16] = "snmp: authorization error"
errtb[17] = "snmp: not writable"
errtb[18] = "snmp: inconsistent name"

local cnf_err = "snmp: invalid session configuration "
errtb[101] = cnf_err.."(version)"
errtb[102] = cnf_err.."(community)"
errtb[103] = cnf_err.."(timeout)"
errtb[104] = cnf_err.."(retries)"
errtb[105] = cnf_err.."(peer address)"
errtb[106] = cnf_err.."(port)"
errtb[107] = cnf_err.."(callback)"
errtb[108] = cnf_err.."(trap)"
errtb[109] = cnf_err.."(inform)"
local opt_err = "snmp: invalid configuration for SNMPv1 session "
errtb[110] = opt_err.."(inform)"
errtb[111] = cnf_err.."(sprintvar)"
errtb[112] = cnf_err.."(sprintval)"
errtb[113] = cnf_err.."(user)"
errtb[114] = cnf_err.."(securityLevel)"
errtb[115] = cnf_err.."(authPassphrase, password)"
errtb[116] = cnf_err.."(privPassphrase, password)"
errtb[117] = cnf_err.."(engineBoots)"
errtb[118] = cnf_err.."(engineTime)"
errtb[119] = opt_err.."(includeroot)"

errtb[120] = "snmp: invalid session"
errtb[121] = "snmp: invalid variable type"
errtb[122] = "snmp: invalid variable name"

errtb[123] = "snmp: invalid argument (non-repeaters)"
errtb[124] = "snmp: invalid argument (max-repetitions)"

errtb[125] = "snmp: invalid operation for SNMPv1 session (inform)"
errtb[126] = "snmp: invalid argument (trap OID)"

errtb[190] = "snmp: no response (timeout)"
errtb[191] = "snmp: internal failure"
errtb[192] = "snmp: bad argument"
errtb[193] = "snmp: oid not increasing"
errtb[194] = "snmp: engineID probe failed"
errtb[195] = "snmp: bad security model"
errtb[196] = "snmp: bad security name"
errtb[197] = "snmp: bad group name"

------------------------------------------------------------------------------
-- Returns nil + error message in case of errors.
-- @param errnum number - Error number.
-- @param message string - function's message to append.
-- @return nil, "errormsg (MESSAGE)"
------------------------------------------------------------------------------
local function FAIL(err, message)
  local rmsg
  if type(err) == "number" then
    rmsg = errtb[err]
  elseif type(err) == "string" then
    rmsg = err
  end
  if message then
    rmsg = rmsg .. " (" .. message ..")"
  end
  return nil, rmsg
end

------------------------------------------------------------------------------
-- Request Types
------------------------------------------------------------------------------
GET_REQ     = 1
GETNEXT_REQ = 2
SET_REQ     = 3
BULK_REQ    = 5
INFO_REQ    = 6

------------------------------------------------------------------------------
-- Mib type codes
------------------------------------------------------------------------------
NOSUCHOBJECT   = 128
NOSUCHINSTANCE = 129
ENDOFMIBVIEW   = 130

TYPE_OTHER       =  0
TYPE_OBJID       =  1
TYPE_OCTETSTR    =  2
TYPE_INTEGER     =  3
TYPE_NETADDR     =  4
TYPE_IPADDR      =  5
TYPE_COUNTER     =  6
TYPE_GAUGE       =  7
TYPE_TIMETICKS   =  8
TYPE_OPAQUE      =  9
TYPE_NULL        = 10
TYPE_COUNTER64   = 11
TYPE_BITSTRING   = 12
TYPE_NSAPADDRESS = 13
TYPE_UINTEGER    = 14
TYPE_UNSIGNED32  = 15
TYPE_INTEGER32   = 16

TYPE_SIMPLE_LAST = 16

TYPE_TRAPTYPE	 = 20
TYPE_NOTIFTYPE   = 21
TYPE_OBJGROUP	 = 22
TYPE_NOTIFGROUP	 = 23
TYPE_MODID	 = 24
TYPE_AGENTCAP    = 25
TYPE_MODCOMP     = 26

TYPE_FLOAT       = 120
TPYE_DOUBLE      = 121
TYPE_INTEGER64   = 122
TYPE_UNSIGNED64  = 123

------------------------------------------------------------------------------
-- Mib type names
------------------------------------------------------------------------------
typetb = {
  "OBJECT IDENTIFIER",
  "OCTET STRING",
  "INTEGER",
  "NetworkAddress",
  "IpAddress",
  "Counter",
  "Gauge32",
  "TimeTicks",
  "Opaque",
  "NULL",
  "Counter64",
  "BIT STRING",
  "NsapAddress",
  "UInteger",
  "UInteger32",
  "Integer32",
  "",
  "",
  "",
  "TRAP-TYPE",
  "NOTIFICATION-TYPE",
  "OBJECT-GROUP",
  "NOTIFICATION-GROUP",
  "MODULE-IDENTITY",
  "AGENT-CAPABILITIES",
  "MODULE-COMPLIANCE"
}
typetb[0] = "OTHER"
typetb[120] = "Opaque: Float"
typetb[121] = "Opaque: Double"
typetb[122] = "Opaque: Integer64"
typetb[123] = "Opaque: Unsigned64"

typetb[128] = "NO SUCH OBJECT"
typetb[129] = "NO SUCH INSTANCE"
typetb[130] = "END OF MIB VIEW"

------------------------------------------------------------------------------
-- 
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- Return comprimated varlist result.
-- @param vl table - Varlist.
-- @param err string - error or nil.
-- @param errindex number - index of failure varbind in varlist.
-- @return varlist or nil + errormessage on failure.
------------------------------------------------------------------------------
local function retvarlist(vl, err, errindex)
  if err then
    if errindex then 
      return FAIL(err, "in index " .. tostring(errindex))
    else
      return FAIL(err)
    end
  else
    return vl
  end
end


------------------------------------------------------------------------------
-- Print an object value
-- @param vb Variable binding or value.
-- @return formatted string for printing.
------------------------------------------------------------------------------
function sprintval2(vb)
 if type(vb) ~= "table" then
   if vb then
     return tostring(vb)
   else
     return "<NULL>"
   end
 end
 local value = vb.value
 if not value then
   return "<NULL>"
 end
 local type = vb.type
 if type == TYPE_TIMETICKS then
   local days,hours,minutes,seconds,deci,ticks
   if (value.days) then days = value.days else days = 0 end
   if (value.hours) then hours = value.hours else hours = 0 end
   if (value.minutes) then minutes = value.minutes else minutes = 0 end
   if (value.seconds) then seconds = value.seconds else seconds = 0  end
   if (value.deciseconds) then deci= value.deciseconds else deci= 0 end
   if (value.ticks) then ticks= value.ticks else ticks= 0 end
   return string.format("%dd %d:%d:%d.%d (%d)",days,hours,minutes,seconds,deci,ticks)
 elseif (type == TYPE_INTEGER) or (type == TYPE_UINTEGER) then
   local enums = mib.enums(vb.oid)
   if enums and enums[value] then
       return enums[value].."("..value..")"
   end
 elseif (type == TYPE_OBJID) then
   local name = mib.name(value)
   if name ~= value then
     return name.." ("..value..")"
   else
     return value
   end
 end
 return tostring(value)
end

------------------------------------------------------------------------------
-- Print an object variable.
-- @param vb table - Variable binding.
-- @return Formatted string for printing.
------------------------------------------------------------------------------
function sprintvar2(vb)
  if type(vb) ~= "table" then 
    return "<Invalid varbind>"
  end
  local name = mib.name(vb.oid) ---> aceitar ja' receber nome pronto?
  if not name then
    name = ""
  end
  return string.format("%s (%s) = %s",name,sprint_type(vb.type),sprintval2(vb))
end

------------------------------------------------------------------------------
-- Print an object type.
-- @param t Variable binding or type code.
-- @return Formatted string for printing.
------------------------------------------------------------------------------
function sprint_type(t)
  local tCode
  if type(t) == "table" then
    tCode = tonumber(t.type or mib.type(t.oid))
  elseif type(t) == "number" then
    tCode = tonumber(t)
  elseif type(t) == "string" then
    tCode = mib.type(t)
  end
  if tCode and typetb[tCode] then
    return typetb[tCode]
  else
    return "<Invalid type>"
  end
end

-- For convenience.
mib.typename = sprint_type

------------------------------------------------------------------------------
-- Print an error.
-- @param err Error code.
-- @return Formatted string for printing.
------------------------------------------------------------------------------
function sprint_error(err)
  local str = errtb[err]
  if str then
    return str
  else
    return "UNKNOWN ERROR"
  end
end

------------------------------------------------------------------------------
-- Check an OID.
-- Does not check whether OID is in the tree.
-- @param oid string - OID string representation.
-- @return OID string, if o.k. Nil otherwise.
------------------------------------------------------------------------------
local function isoid(oid)
  if type(oid) ~= "string" then return FAIL(BADARG) end
  if string.find(string.gsub(oid,"%.%d%d*",""),"^%d%d*$") then
    return oid
  else
    return FAIL("snmp: not an OID")
  end
end

------------------------------------------------------------------------------
-- Eval length of an OID.
-- Does not check whether OID is in the tree.
-- @param oid string - OID string representation.
-- @return OID string, if o.k. Nil otherwise.
------------------------------------------------------------------------------
local function oidlen(oid)
  local oid, err = isoid(oid)
  if not oid then return FAIL("snmp: not an OID") end
  local n = 0
  string.gsub(oid, "%.", function(v) 
			   n = n + 1 
			 end)
  return n + 1
end

------------------------------------------------------------------------------
-- Eval a base OID of certain length.
-- Does not check whether OID is in the tree.
-- @param oid string - OID string representation.
-- @param len number - Length of base OID.
-- @return Base OID string, if o.k. nil otherwise.
------------------------------------------------------------------------------
local function oidbase(oid, len)
  local err
  local len = len or oidlen(oid)
  oid, err = isoid(oid)
  if not oid then return nil, err end
  local rv = ""
  for d, p in string.gmatch(oid,"(%d+)(%.*)") do
    rv = rv .. d
    len = len - 1
    if len == 0 then 
      return rv
    else
      rv = rv .. (p or "")
    end
  end
  print("###", oid, rv)
  return rv
end

------------------------------------------------------------------------------
-- Translate an OID into a table.
-- Does not check whether OID is in the tree.
-- @param oid string - OID string representation or name.
-- @return Table presentation of an OID: {1,2,17,2,3}.
------------------------------------------------------------------------------
local function oidtotable(oid)
  local err
  oid, err = isoid(oid)
  if not oid then return nil, err end
  local t = {}
  string.gsub(oid, "(%d+)%.*", function(d) table.insert(t, tonumber(d)) end)
  return t, #t
end

------------------------------------------------------------------------------
-- Compare two OIDs.
-- Does not check whether OID is in the tree.
-- @param oid1 string - OID string 1 or name 1.
-- @param oid2 string - OID string 2 or name 2.
-- @return 1 if oid1 > oid2, 0 if oid1 == oid2, -1 if oid1 < oid2.
------------------------------------------------------------------------------
local function oidcompare(oid1, oid2)
  if not isoid(oid1) then return FAIL(BADARG, "oid1") end
  if not isoid(oid2) then return FAIL(BADARG, "oid2") end
  local t1,n1 = oidtotable(oid1)
  local t2,n2 = oidtotable(oid2)

  local n = n1
  if n2 < n1 then 
    n = n2
  end
  for i = 1,n do
    if t1[i] > t2[i] then
      return 1
    elseif t1[i] < t2[i] then
      return -1
    end
  end
  if n1 < n2 then return -1 end
  if n2 < n1 then return 1 end
  return 0
end

------------------------------------------------------------------------------
-- Returns the index of a varbind based on a superordinated OID.
-- @param vb table - Variable name (text or OID).
-- @param tname string - Super-ordinated OID
-- @return Index as string.
------------------------------------------------------------------------------
local function oidindex(oid, base)
  if not isoid(oid) then return FAIL(BADARG, "oid") end
  if not isoid(base) then return FAIL(BADARG, "base") end
  local s, n = string.gsub(oid, "^"..base.."%.(.+)","%1")
  if n > 0 then return s else return "" end
end

------------------------------------------------------------------------------
-- Load a MIB file. 
-- Search in all directories given by MIBDIRS.
-- @param fname string File name.
------------------------------------------------------------------------------
local function load(fname)
  if string.sub(fname, 1, 1) == "/" then
    local tree, err = mib._load(fname)
    if tree then return tree end 
  else 
    local configdirs = string.gsub(config.mibdirs or "", "(%+*)(.+)", "%2")
    local mibdirs = ".:" .. (os.getenv("LUASNMP_MIBDIRS") or os.getenv("MIBDIRS") or configdirs)
    for dir in string.gmatch(mibdirs, "[^:;]+") do
      for _,ext in ipairs{".txt","",".mib"} do
	local fn = dir.."/"..fname..ext
	local f = io.open(fn,"r")
	if f then 
	  f:close() 
	  local tree, err = mib._load(fn)
	  if tree then return tree end
	end
      end
    end
  end
  return nil, "mib: cannot add mib"
end

mib.isoid = isoid
mib.oidlen = oidlen
mib.oidbase = oidbase
mib.oidtotable = oidtotable
mib.oidcompare = oidcompare
mib.oidindex = oidindex
mib.load = load

-- Some other names for sprints.
sprintval = sprint_value
sprinttype = sprint_type
sprintvar = sprint_variable
sprinterr = sprint_error
---------------------------------------------------------------------------
-- Walk the MIB tree
-- @param sess table - Session.
-- @param var table or string - Root object.
-- @return Varbind list with values.
---------------------------------------------------------------------------
function walk(sess, var)
  local oid
  local running = true
  local t = {}
  local root, vb, err
--  if not sess then return nil, errtb[BADSESSION] end
  if not sess then return FAIL(BADSESSION) end
  local var = var or "mib-2"
  if type(var) == "table" then
    oid = mib.oid(var.oid)
  elseif type(var) == "string" then
    oid = mib.oid(var)
  else 
    return FAIL(BADARG, "var")
  end
  if not oid then return nil, errtb[BADOID] end
  root = {oid = oid}
  if sess.includeroot then
    vb, err = sess:get(root)
    if err then return nil, err end
    table.insert(t,vb)
  end
  local rootlen = oidlen(root.oid)
  local vb = root
  local rootoid = root.oid
  local last = rootoid
  while running do
    vb, err = sess:getnext(vb)
    if not vb then return nil, err end
    if err then
      if err == NOSUCHNAME or string.find(err, "no such name") then
	running = false
	return t, nil
      else
	return t, err 
      end
    end
    local oid = vb.oid
    if oidlen(oid) < rootlen or 
      vb.type == ENDOFMIBVIEW or
      not string.find(oid, rootoid) then
      running = false
    else
      if oidcompare(last, oid) >= 0 then
	return nil, errtb[BADOID]
      end
      last = oid
      table.insert(t, vb)
    end
  end
  if not err and #t == 0 then
    vb, err = sess:get(root)
    if err then return t, err end
    table.insert(t, vb)
  end
  return t
end

---------------------------------------------------------------------------
-- Retrieve sorted list of keys of a table
---------------------------------------------------------------------------
function getkeys(t)
  local rv = {}
  for k,v in pairs(t) do
    table.insert(rv, k)
  end
  table.sort(rv)
  return rv
end

---------------------------------------------------------------------------
-- Sorted iteration over a list of keys in table.
---------------------------------------------------------------------------
assert(not _G.spairs, "Symbol 'spairs' already defined")
function _G.spairs(t)
  local keys = getkeys(t)
  local i = 0
  table.sort(keys)
  return function()
	   i = i + 1
	   return keys[i], t[keys[i]]
	 end
end
---------------------------------------------------------------------------
-- Convert formatted time value to varbind.
-- @param s string - Formatted string.
-- @return Varbind.
---------------------------------------------------------------------------
function uptimeS2V(s)
  local ticks = nil
  if type(s) ~= "string" then return FAIL(BADARG) end
  string.gsub(s, "(%d+):(%d+):(%d+):(%d+)%.(%d+)$",
 	      function(d, h, m, s, ds)
		ticks = {
		  days = tonumber(d) or 0,
		  hours = tonumber(h) or 0,
		  minutes = tonumber(m) or 0,
		  seconds = tonumber(s) or 0,
		  deciseconds = tonumber(ds) or 0
		}
		ticks.ticks = ticks.deciseconds +
		  ticks.seconds * 100 +
		  ticks.minutes * 60 * 100 +
		  ticks.hours * 60 * 60 * 100 +
		  ticks.days * 24 * 60 * 60 * 100
	      end)
  return ticks
end

---------------------------------------------------------------------------
-- Convert uptime varbind to string.
-- @param vb table - Varbinding containing sysUpTime.
-- @return Formatted string.
---------------------------------------------------------------------------
function uptimeV2S(vb)
  if type(vb) ~= "table" then return FAIL(BADARG) end
  return string.format("%d:%d:%d:%d.%d",
		       vb.days, vb.hours, vb.minutes,
		       vb.seconds, vb.deciseconds)
end

---------------------------------------------------------------------------
-- A generic trap handler. 
-- Only activated if a user supplied trap callback function has
-- been provided. It also calls the user callback function.
-- NOTE: The scanner of the trap message requires the following log formats
--       settings in snmptrapfmt.conf to work properly:
--       SUBST=\#\ \
--       NODEFMT=ip
--       VARFMT="#[%s] %n (%t) : %v" 
--       LOGFMT="$x#$A#$e#$G#$S#$T$*"
-- @param session table - Session that captures the trap.
-- @param msg string - Message from snmptrapd.
--                     See snmptrapd.conf manual page for content.
-- @return none.
---------------------------------------------------------------------------
function __trap(session, msg)
   local host, src, vbs, sip, dip, sport, dport, uptimeName, uptimeVal, vbs, ip, port
   -- debugging: uncomment if desired
   --print(string.format("  session.name=%s", session.name))
   --print(string.format("  generic_trap(): msg = %q", msg))
   --print(string.format("  netsnmp version: %s", snmp.getversion()))
   --print(string.format("  snmp._SYSTEM: %s", snmp._SYSTEM))

   -- The message may ne different for Cygwin and Linux.
   -- We keep the differentiation even if not really required.
   if snmp._SYSTEM == "Cygwin"  and snmp.getversion() > "5.3" then
      string.gsub(msg, 
		  "^%s*([%w%.]+)%s+(%w+):%s*%[[%d%.]+%]%-%>%[([%d%.]+)%]:(%d+)%s+([^%s]+)%s+([^%s]+)%s+(.*)",
		  function(...) 
		     host, proto, ip, port, uptimeName, uptimeVal, vbs = select(1, ...) 
		  end)
      -- debugging:
      -- print(string.format("  host=%q, proto=%q, ip=%q, port=%q, uptimeName=%q, uptimeVal=%q, vbs=%q",
      -- host, proto, ip, port, uptimeName, uptimeVal, vbs))
   elseif snmp.getversion() > "5.5" then
      string.gsub(msg, 
		  -- Example msg:
		  -- " localhost UDP: [127.0.0.1]->[127.0.0.1]:-6577 \
		  -- iso.3.6.1.2.1.1.3.0 0:2:11:01.53 iso.3.6.1.6.3.1.1.4.1.0 ccitt.0 iso.3.6.1.2.1.1.5.0 \"hello\""		  
		  "^%s*([%w%.]+)%s+(%w+):%s*%[([%d%.]+)%]:([%d]+)%-%>%[([%d%.]+)%]:([%-%d]+)%s+([^%s]+)%s+([^%s]+)%s+(.*)",
		  function(...) 
		     host, proto, sip, sport, dip, dport, uptimeName, uptimeVal, vbs = select(1, ...) 
                     ip = sip
                     port = sport
		     -- debugging:
		     -- print("dissected msg:", host, proto, sip, sport, dip, dport, uptimeName, uptimeVal, vbs)
		  end)
      -- debugging: uncomment if desired
      -- print(string.format("  host=%q, proto=%q, ip=%q, port=%q, uptimeName=%q, uptimeVal=%q, vbs=%q",
      --                     host, proto, ip, port, uptimeName, uptimeVal, vbs))
   else
      string.gsub(msg, "([%w%.]+)%s+([%d%.]+)%s+([^%s]+)%s+([^%s]+)%s+(.*)",
		  function(...)
		     local arg = {select(1, ...)}
		     host = arg[1]
		     src = arg[2]
		     uptimeName = arg[3]
		     uptimeVal = uptimeS2V(arg[4])
		     vbs = arg[5]
		  end)
   end
   if dip == session.peer_ip or true then
      -- Convert variable bindings
      local vlist
      if string.find(snmp.getversion(), "5.4") then
	 vlist = {{oid = uptimeName, type = mib.type("sysUpTime"), value = uptimeVal}}
      elseif string.find(snmp.getversion(), "5.3") then
	 -- Note: we don't get a reasonable type value for sysUpTimeInstance in net-snmp 5.3 
	 vlist = {{oid=uptimeName, type=mib.type("sysUpTime"), value = uptimeVal}}
      else
	 vlist = {{oid=uptimeName, type=mib.type(uptimeName), value = uptimeVal}}
      end
      string.gsub(vbs, "([^%s]+)%s+([^%s]+)%s*",
		  function(name, val)
		     local oid = name
		     local typ = mib.type(name)
		     local value = mib.oid(val) or uptimeS2V(val) or val
		     table.insert(vlist, {oid=oid, type=typ, value=value})
		  end)
      --  debugging:
      -- table.foreach(vlist, function(k,v) table.foreach(v, print) end)
      session.usertrap(vlist, ip, port, host, session)
   end
end


---------------------------------------------------------------------------
-- Create a new variable binding.
-- @param name string - Name or OID of variable.
-- @param value any - Value of variable.
-- @param type number (opt) - Type of the object.
-- @return Variable binding with metamethods set.
---------------------------------------------------------------------------
function newvar(name, value, typ, session)
  local oid = mib.oid(name) or name
  local vb = {oid = oid, type = typ or mib.type(oid), value = value}
  if session then vb[".session"]  = session end
  setmetatable(vb, __vbindmetatable)
  return vb
end

---------------------------------------------------------------------------
-- Print a hexstring (key) in the form 0x1234etc.
-- @param key string - Hexstring (may contain embedded zeros).
-- @param len number - Length of the (sub)string to evaluate.
-- @return String containing a readable presentation of the hexstring.
---------------------------------------------------------------------------
function sprintkeyx(key, len)
  local s = "0x"
  local slen = string.len(key)
  local len = len or slen
  if len > slen then len = slen end
  for i = 1, len do
    s = s..string.format("%02X", string.byte(key, i))
  end
  return s
end

---------------------------------------------------------------------------
-- Print a hexstring (key) in the OID form 1.2.3.4.
-- @param key string - Hexstring (may contain embedded zeros).
-- @param len number - Length of the (sub)string to evaluate.
-- @return String containing an OID presentation of the input string.
---------------------------------------------------------------------------
function sprintkeyd(key, len)
  local s = ""
  local slen = string.len(key)
  local len = len or slen
  if len > slen then len = slen end
  for i = 1, len do
    s = s..string.format("%d", string.byte(key,i))
    if i < len then s = s .. "." end
  end
  return s
end

---------------------------------------------------------------------------
-- Print a hexstring (key) in the form 01:02:03:etc.
-- @param key string - Hexstring (may contain embedded zeros).
-- @param len number - Length of the (sub)string to evaluate.
-- @return String containing a presentation of the hexstring that can
--         be evaluated by snmp.set(SESSION, VAR)
---------------------------------------------------------------------------
function sprintkey(key, len)
  local slen = string.len(key)
  local len = len or slen
  local s = ""
  if len > slen then len = slen end
  for i = 1, len do
    s = s..string.format("%02x", string.byte(key, i))
    if i < len then s = s .. ":" end
  end
  return s
end

---
-- Shortcuts - probably more SNMP like names.
--
key2oid = sprintkeyd
key2hex = sprintkeyx
key2octet = sprintkey
octetstring = sprintkey
hexstring = sprintkeyx

---------------------------------------------------------------------------
-- Print a string as OID. The length is prepended to the OID string
-- representing the actual string data.
-- @param str string - String to convert.
-- @return String containint an OID in the from LENGTH.CHAR.CHAR.etc.
---------------------------------------------------------------------------
function stringoid(str)
  local len = string.len(str)
  if len == 0 then
    return "0"
  else
    return string.format("%d.%s", string.len(str), key2oid(str))
  end
end

mib.stringoid = stringoid
---------------------------------------------------------------------------
-- Create an index in OID from from the given parameters.
-- @param arg table - Table containing a variable number of parameters
-- @return String containing the index as OID.
---------------------------------------------------------------------------
function instance(...)
  local oid = ""
  arg = {select(1, ...)}
  for k,v in ipairs(arg) do
    if type(v) == "number" then
      oid = oid .. string.format(".%d", v)
    elseif type(v) == "string" then
      if isoid(v) then
	oid = oid .. string.format(".%d.%s",oidlen(v), v)
      else
	oid = oid .. string.format(".%s", stringoid(v))
      end
    elseif type(v) == "boolean" then
      if v == true then oid = oid .. ".1" else
	oid = oid .. ".0" end
    elseif type(v) == "table" then
      oid = oid .. instance(unpack(v))
    else 
      return FAIL(BADARG, "arg["..k.."]") 
    end
  end
  return oid
end

mkindex = instance
mib.instance = instance

------------------------------------------------------------------------------
-- Change user's password.
-- @param session table - Active session.
-- @param oldpw string - Old password.
-- @param newpw string - New password.
-- @param flag string (opt) - Indicates what pass phrase to
--        change: "a" = auth, "ap" = auth + priv, "p" = priv.
-- @param user (opt) string - What user to change.
-- @param engineID (opt) hexstring - Context engine ID to use.
-- @return varlist on success, nil + error message of failure.
------------------------------------------------------------------------------
function newpassword(session, oldpw, newpw, flag, user, engineID)
  local authKeyChange, privKeyChange

  local doauth, dopriv = false, false
  -- Be sure we run a version 3 session
  -- Do we really need this? Don't think so (leu)
  if session.version ~= SNMPv3 then return FAIL(BADSESSION) end

  -- What to change: auth=a, priv=p or both=ap
  flag = flag or "a"
  if string.find(flag,"a") then doauth = true end
  if string.find(flag,"p") then dopriv = true end

  -- What user to change
  if not user then
    -- session user
    authKeyChange = keyOid.ownAuth
    privKeyChange = keyOid.ownPriv
    user = session.user
  else
    -- defined user
    if type(user) ~= "string" then 
      return nil, errtb[BADARG] .. " (user)"
    end
    authKeyChange = keyOid.auth
    privKeyChange = keyOid.priv
  end

  -- Engine ID to use
  if not engineID then
    local t = session:details()
    if t.contextEngineIDLen == 0 then
      -- we need an engineID and don't have one: probe with empty get-request
      local vb, err = session:get(nil)
      if not vb or err then return nil, errtb[BADENGPROBE] end
    end
    t = session:details()
    engineID = t.contextEngineID
  end
  -- check password lengths
  if type(oldpw) ~= "string" and string.len(oldpw) < 8 then
    return FAIL(BADARG, "oldpw")
  end
  if type(newpw) ~= "string" and string.len(oldpw) < 8 then
    return FAIL(BADARG, "newpw")
  end

  -- create old and new keys
  local authProto
  if session.authType == "MD5" then
    authProto = usmProtocol.HMACMD5Auth
  else
    authProto = usmProtocol.HMACSHA1Auth
  end
  local oldKu, oldKuLen = createkey(session, oldpw, authProto)
  if not oldKu then return nil, oldKuLen end
  local newKu, newKuLen = createkey(session, newpw, authProto)
  if not newKu then return nil, newKuLen end
  
  -- create old and new localized keys
  local oldKul, oldKulLen = createlocalkey(session, oldKu, authProto, engineID)
  if not oldKul then return nil, oldKulLen end
  local newKul, newKulLen = createlocalkey(session, newKu, authProto, engineID)
  if not newKul then return nil, newKulLen end

  -- transformations
  if dopriv then
    if session.privType == "DES" or session.privType == "AES" then
      oldKulPrivLen, newKulPrivLen = 16, 16
    end
    oldKulPriv = oldKul
    newKulPriv = newKul
  end

  -- create keychange string
  local keychg, keychgpriv, keychglen, keychgprivlen
  if doauth then
    keychg, keychglen = keychange(session, oldKul, newKul, authProto)
    if not keychg then return FAIL("snmp: cannot create keychange") end
  end

  if dopriv then
    keychgpriv, keychgprivlen = keychange(session, oldKulPriv, newKulPriv, authProto)
    if not keychgpriv then return FAIL("snmp: cannot create keychange priv") end
  end

  -- setup varbind list
  local vl = {}
  if doauth then
    local vb = newvar(string.format("%s.%d.%s.%d.%s",
				    authKeyChange,
				    string.len(engineID), key2oid(engineID),
				    string.len(user), key2oid(user)), 
		      key2octet(keychg, keychglen),
		      snmp.TYPE_OCTETSTR)
    table.insert(vl, vb)
  end

  if dopriv then
    local vb = newvar(string.format("%s.%d.%s.%d.%s",
 				    privKeyChange,
 				    string.len(engineID), key2oid(engineID),
 				    string.len(user), key2oid(user)),
		      key2octet(keychgpriv, keychgprivlen),
		      snmp.TYPE_OCTETSTR)
  end
  -- set request
  vl, err, errindex = session:set(vl)
  if err then
    if errindex then 
      return FAIL(err,"index " .. tostring(errindex))
    else
      return FAIL(err)
    end
  else
    return vl
  end
end

------------------------------------------------------------------------------
-- Create user and optionally take authentication parameters
-- from another user.
-- @param session table - Session for performing the operation.
-- @param user string - Name of user to create.
-- @param clonefrom string (opt) - Name of user to clone.
-- @return Varlist or nil + errormessage
------------------------------------------------------------------------------
function createuser(session, user, clonefrom, engineID)
  local err

  if type(user) ~= "string" then return FAIL(BADARG, "user") end

  -- Engine ID to use
  if not engineID then
    local t = session:details()
    if t.contextEngineIDLen == 0 then
      -- we need an engineID and don't have one: probe with empty get-request
      local vb, err = session:get(nil)
      if not vb then return FAIL(BADENGPROBE) end
    end
    t = session:details()
    engineID = t.contextEngineID
  end

  -- Prepare and execute the request
  if clonefrom then
    -- create clonefrom
    if type(clonefrom) ~= "string" then 
      return FAIL(BADARG, "clonefrom")
    end
    local vl = {}
    -- oid is the new user
    local vb = newvar(string.format("%s.%d.%s.%d.%s",
				    usmOid.userStatus,
				    string.len(engineID), key2oid(engineID),
				    string.len(user), key2oid(user)),
		      -- value is the row status
		      rowStatus.createAndGo)
    table.insert(vl, vb)
    -- oid is the new user
    vb = newvar(string.format("%s.%d.%s.%d.%s",
			      usmOid.userCloneFrom,
			      string.len(engineID), key2oid(engineID),
			      string.len(user), key2oid(user)),
		-- value is the entry of clonefrom user
		string.format("%s.%d.%s.%d.%s",
			      usmOid.userSecurityName,
			      string.len(engineID), key2oid(engineID),
			      string.len(clonefrom), key2oid(clonefrom)))
    table.insert(vl, vb)

    local vl, err, errindex = session:set(vl)
    if err then
      if errindex then
	return FAIL(err, "index " .. tostring(errindex))
      else
	return FAIL(err)
      end
    else
      return vl
    end
  else
    -- create
    local vb = newvar(string.format("%s.%d.%s.%d.%s",
				    usmOid.userStatus,
				    string.len(engineID), key2oid(engineID),
				    string.len(user), key2oid(user)),
		      rowStatus.createAndWait)
    vb, err = session:set(vb)
    return vb, err
  end
end

------------------------------------------------------------------------------
-- Active a created user and clone authentication from another
-- user.
-- @param session table - Session for performing the operation.
-- @param user string - Name of user to create.
-- @param clonefrom string - Name of user to clone.
-- @return Varlist or nil + errormessage
------------------------------------------------------------------------------
function clonefromuser(session, user, clonefrom, engineID)
  local err

  -- sanity checks
  if type(clonefrom) ~= "string" then return FAIL(BADARG, "clonefrom") end
  if type(user) ~= "string" then return FAIL(BADARG, "user") end

  -- Engine ID to use
  if not engineID then
    local t = session:details()
    if t.contextEngineIDLen == 0 then
      -- we need an engineID and don't have one: probe with empty get-request
      local vb, err = session:get(nil)
      if not vb then return FAIL(BADENGPROBE) end
    end
    t = session:details()
    engineID = t.contextEngineID
  end

  local vl = {}
  -- Set user row active
  local vb = newvar(string.format("%s.%d.%s.%d.%s",
				  usmOid.userStatus,
				  string.len(engineID), key2oid(engineID),
				  string.len(user), key2oid(user)),
		    rowStatus.active)
  table.insert(vl, vb)

  -- oid is the new user
  vb = newvar(string.format("%s.%d.%s.%d.%s",
			    usmOid.userCloneFrom,
			    string.len(engineID), key2oid(engineID),
			    string.len(user), key2oid(user)),
	      -- value is the entry of clonefrom user
	      string.format("%s.%d.%s.%d.%s",
			    usmOid.userSecurityName,
			    string.len(engineID), key2oid(engineID),
			    string.len(clonefrom), key2oid(clonefrom)))
  table.insert(vl, vb)

  -- set request
  local vl, err, errindex = session:set(vl)
  if err then
    if errindex then 
      return FAIL(err,"index " .. tostring(errindex))
    else
      return FAIL(err)
    end
  else
    return vl
  end
end

------------------------------------------------------------------------------
-- Delete a user.
-- @param session table - Session for performing the operation.
-- @param user string - Name of user to delete.
-- @return varbind or nil + errormessage 
------------------------------------------------------------------------------
function deleteuser(session, user, engineID)

  -- Sanity check
  if type(user) ~= "string" then return FAIL(BADARG, "user") end

  -- Engine ID to use
  if not engineID then
    local t = session:details()
    if t.contextEngineIDLen == 0 then
      -- we need an engineID and don't have one: probe with empty get-request
      local vb, err = session:get(nil)
      if not vb then return FAIL(BADENGPROBE) end
    end
    t = session:details()
    engineID = t.contextEngineID
  end

  -- delete
  local vb = newvar(string.format("%s.%d.%s.%d.%s",
				  usmOid.userStatus,
				  string.len(engineID), key2oid(engineID),
				  string.len(user), key2oid(user)),
		    rowStatus.destroy)
  vb, err = session:set(vb)
  return vb, err
end

------------------------------------------------------------------------------
-- Create security name to group mapping.
-- @param session table - Valid session.
-- @param secmodel string - Security model 'SNMPv1', 'SNMPv2', 'USM'
-- @param secname string - Security name.
-- @param groupname string - Group name.
-- @return varlist or nil + erromessage on failure
------------------------------------------------------------------------------
function createsectogroup(session, secmodel, secname, groupname)
  -- Sanity checks
  if type(secmodel) ~= "string" then return FAIL(BADARG, "secmodel") end
  secmodel = secmodels[string.upper(secmodel)]
  if type(secname) ~= "string" then return FAIL(BADARG, "secname") end
  if type(groupname) ~= "string" then return FAIL(BADARG, "groupname") end

  local vl = 
    newvar(vacmOid.sec2GroupStatus..instance(secmodel, secname),
	   rowStatus.createAndGo) ..
    newvar(vacmOid.groupName..instance(secmodel, secname),
	   groupname)
  -- set request
  local vl, err, errindex = session:set(vl)
  return retvarlist(vl, err, errindex)
end


------------------------------------------------------------------------------
-- Delete security name to group mapping.
-- @param session table - Valid session.
-- @param secmodel string - Security model 'SNMPv1', 'SNMPv2', 'USM'
-- @param secname string - Security name.
-- @return varlist or nil + erromessage on failure
------------------------------------------------------------------------------
function deletesectogroup(session, secmodel, secname)
  local err
  -- Sanity checks
  if type(secmodel) ~= "string" then FAIL(BADARG, "secmodel") end
  secmodel = secmodels[string.upper(secmodel)]
  
  if type(secname) ~= "string" then return FAIL(BADARG, "secname") end
  local vb = newvar(vacmOid.sec2GroupStatus..instance(secmodel, secname),
		    rowStatus.destroy)

  -- set request
  vb, err = session:set(vb)
  return vb, err
end

------------------------------------------------------------------------------
-- Create a view for a subtree
-- @param session table - Valid session.
-- @param viewname string - Name for the created view.
-- @param subtree oid - OID of view's subtree.
-- @param mask string - Bitmask.
-- @param flag string - "exc[lude]" or "inc[lude]" (default).
-- @return varlist or nil + erromessage on failure
------------------------------------------------------------------------------
function createview(session, viewname, subtree, mask, flag)
  local err, included
  if type(viewname) ~= "string" then return 
    nil, errtb[BADARG].." (viewname)" 
  end
  if not isoid(subtree) then return FAIL(BADARG, "subtree") end
  if type(mask) ~= "string" then return FAIL(BADARG, "mask") end
  local viewmask = ""
  string.gsub(mask, "([0-9A-Fa-f])([0-9A-Fa-f]*)", 
	      function(d1, d2)
		if d2 == "" then d2 = "0" end
		if string.len(d2) ~= 1 then
		  return nil, errtb[BADARG] .. " (mask)" end
		viewmask = viewmask .. string.char(tonumber(d1,16)*16+tonumber(d2,16))
	      end)
  if not flag then flag = "include" end
  flag = string.lower(flag)
  if string.sub(flag, 1,3) == "inc" then
    included = 1
  elseif string.sub(flag, 1, 3) == "exc" then
    included = 2
  end
  local vl = 
    newvar(vacmOid.viewTreeFamilyStatus .. instance(viewname, subtree),
	   rowStatus.createAndGo) ..
    newvar(vacmOid.viewTreeFamilyMask .. instance(viewname, subtree),
	   key2octet(viewmask)) ..
    newvar(vacmOid.viewTreeFamilyType .. instance(viewname, subtree),
	   included)

  -- set request
  local vl, err, errindex = session:set(vl)
  return retvarlist(vl, err, errindex)
end

------------------------------------------------------------
-- Delete a view.
-- @param session table - Valid session.
-- @param viewname string - Name for the created view.
-- @param subtree oid - OID of view's subtree.
-- @return varbind  or nil + erromessage on failure
------------------------------------------------------------
function deleteview(session, viewname, subtree)

  if type(viewname) ~= "string" then return FAIL(BADARG, "viewname") end
  if not isoid(subtree) then return FAIL(BADARG, "subtree") end
  local vb = newvar(vacmOid.viewTreeFamilyStatus .. instance(viewname, subtree),
		    rowStatus.destroy)
  -- set request
  local vb, err = session:set(vb)
  return vb, err
end

------------------------------------------------------------------------------
-- Create Access Entry.
-- @param session table - Valid session.
-- @param group string - Group name.
-- @param secmodel string - Security model 'SNMPv1', 'SNMPv2', 'USM'
-- @param seclevel string - Security level 'authNoPriv' etc.
-- @param match string - View ma
-- @param secname string - Security name.
-- @return varlist or nil + erromessage on failure
------------------------------------------------------------------------------
function createaccess(session, group, secmodel, seclevel, match, 
		      readview, writeview, notifyview, context)
  if type(secmodel) ~= "string" then return FAIL(BADARG, "secmodel") end
  secmodel = secmodels[string.upper(secmodel)]
  if type(seclevel) ~= "string" then return FAIL(BADARG, "secname") end
  if not seclevels[seclevel] then return FAIL(BADARG, "seclevel") end
  seclevel = seclevels[seclevel]
  if type(match) ~= "string" then return FAIL(BADARG, "match") end
  local nmatch
  if match == "exact" then
    nmatch = 1
  elseif match == "prefix" then
    nmatch = 2
  end
  if not context then context = "" end
  local inst = instance(group, context, secmodel, seclevel)
  local vl = 
    newvar(vacmOid.accessStatus .. inst, rowStatus.createAndGo) ..
    newvar(vacmOid.accessContextMatch .. inst, nmatch) ..
    newvar(vacmOid.accessReadViewName .. inst, key2octet(readview)) ..
    newvar(vacmOid.accessWriteViewName .. inst, key2octet(writeview)) ..
    newvar(vacmOid.accessNotifyViewName .. inst, key2octet(notifyview))

  -- set request
  local vl, err, errindex = session:set(vl)
  return retvarlist(vl, err, errindex)
end

------------------------------------------------------------------------------
-- Delete security name to group mapping.
-- @param session table - Valid session.
-- @param secmodel string - Security model 'SNMPv1', 'SNMPv2', 'USM'
-- @param secname string - Security name.
-- @return varlist or nil + erromessage on failure
------------------------------------------------------------------------------
function deleteaccess(session, group, secmodel, seclevel, context)
  if type(secmodel) ~= "string" then return FAIL(BADARG, "secmodel") end
  secmodel = secmodels[string.upper(secmodel)]
  if type(seclevel) ~= "string" or not seclevels[seclevel] then 
    return FAIL(BADARG, "seclevel") 
  end
  seclevel = seclevels[seclevel]

  if not context then context = "" end

  local inst = instance(group, context, secmodel, seclevel)
  local vb = newvar(vacmOid.accessStatus .. inst, rowStatus.destroy)

  -- set request
  local vb, err = session:set(vb)
  return vb, err
end

------------------------------------------------------------------------------
-- Clones a valid session.
-- Note: We disable session cloning because it leads to mangling of NET-SNMPs
--       user list and hence doesn't work reliable enough. (NET-SNMP 5.7)
-- @param parent table - Parent session.
-- @param config table - Configuration (overrides parent's configuration)
-- @return New session if o.k. Nil + error message otherwise.
------------------------------------------------------------------------------
function __clone(parent, config)
  local new = {parent=parent}
  config = config or {}
  -- sanity checks
  if config.version then
    if config.version ~= parent.version then return FAIL(BADVERSION) end
  end
  for k, v in pairs(parent) do
    if parent.version ~= SNMPv3 then
      if (k ~= "inform") then
	new[k] = v
      end
    else
      if config.password then
	if (k ~= "authPassphrase") and (k ~= "privPathphrase") then
	  new[k] = v
	end
      else
	new[k] = v
      end
    end
  end
  for k, v in pairs(config or {}) do
    new[k] = config[k]
  end
  return open(new)
end

------------------------------------------------------------------------------
-- Table with session properties accessible using session.NAME using
-- __index metamethod. Used to retrieve C internals provided by 
-- snmp.details() function.
------------------------------------------------------------------------------
local sessionproperties = {
  contextEngineID = function(self) return details(self).contextEngineID end,
  contextEngineIDLen = function(self) return details(self).contextEngineIDLen end,
  securityEngineID = function(self) return details(self).securityEngineID end,
  securityEngineIDLen = function(self) return details(self).securityEngineIDLen end,
  engineBoots = function(self) return details(self).engineBoots end,
  engineTime = function(self) return details(self).engineTime end,
  isAuthoritative = function(self) return details(self).isAuthoritative end
}

---------------------------------------------------------------------------
-- Create a new SNMP session.
-- @param session table - Base parameters.
-- @return Active session.
---------------------------------------------------------------------------
function open (session)
  
  if not session then
    session = {}
  end
  
  -- Be sure to have the correct parameter type
  if type(session)~="table" then 
    return FAIL(BADSESSION)
  end

  if not session.name then
    session.name = "nobody"
  end

  -- SNMP Version: v1, v2c (default) or v3
  if not session.version then 
    session.version=tonumber(config.defVersion) or SNMPv2C
  end
  if (session.version ~= SNMPv1 and 
      session.version ~= SNMPv2C and 
	session.version ~= SNMPv3)  then
    return FAIL(BADVERSION)
  end
  
  -- Printing variables
  if session.sprintvar then
    if type(session.sprintvar ) ~= "function" then
      return FAIL(BADPRINTVAR)
    end
  else
    session.sprintvar = sprint_variable
  end

  -- Printing values
  if session.sprintval then
    if type(session.sprintval ) ~= "function" then
      return FAIL(BADPRINTVAL)
    end
  else
    session.sprintval = sprint_value
  end
  
  -- Version 2: community: any or  public (default)
  if session.version == SNMPv2c then
    if not session.community then
      session.community = config.defCommunity or "public"
    end
    if type(session.community)~="string" then
      return FAIL(BADCOMMUNITY)
    end
  end

  -- Version 3: ...
  if session.version == SNMPv3 then
    
    -- username: any
    if not session.user then
      session.user = config.defSecurityName
    end
    if not session.user then 
      return FAIL(BADUSER)
    end
    
    -- security level: authPriv, authNoPriv (default) or noAuthNoPriv
    if not session.securityLevel then
      session.securityLevel = config.defSecurityLevel or "authNoPriv"
    end
    if not seclevels[session.securityLevel] then
      return FAIL(BADSECLEVEL)
    else
      session._securityLevel = seclevels[session.securityLevel]
    end
    
    -- authentication protocol: MD5 (default) or SHA
    if not session.authType then
      session.authType = config.defAuthType or "MD5"
    end
    
    -- authentication passphrase: any
    if not session.password and not session.authPassphrase  then
      session.authPassphrase = config.defPassphrase or config.defAuthPassphrase
    else
      session.authPassphrase = session.authPassphrase or session.password
    end
    if not session.authPassphrase  then
      return FAIL(BADPASSPHRASE)
    end

    -- encryption protocol: DES (default) or AES
    if not session.privType then
      session.privpType = config.defPrivType or "DES"
    end

    -- privacy passphrase: any
    if not session.password and not session.privPassphrase  then
      session.privPassphrase = config.defPassphrase or config.defPrivPassphrase
    else
      session.privPassphrase = session.privPassphrase or session.password
    end
    if not session.privPassphrase  then
      return FAIL(BADPRIVPASSPHRASE)
    end

    -- context:
    if not session.context then
      session.context = ""
    end

    -- authentication engine ID: 
    if not session.engineID then
      session.engineID = nil
    end
    
    -- context engine ID: 
    if not session.contextID then
      session.contextID = session.engineID 
    end
    
    -- engine boots: not supported yet
    if not session.engineBoots then
      session.engboots = nil
    else
      return FAIL(BADENGBOOTS)
    end
    
    -- engine time: not supported yet
    if not session.engineTime then
      session.engtime = nil
    else
      return FAIL(BADENGTIME)
    end
  end
  
  -- timeout: any or 1s (default)
  if not session.timeout then
    session.timeout = 1
  else
    session.timeout = tonumber(session.timeout)
    if not session.timeout then
      return FAIL(BADTIME)
    elseif session.timeout < 0 then
      return FAIL(BADTIME)
    end
  end

  -- retries: any or 5 (default)
  if not session.retries then
    session.retries = 5
  else
    session.retries = tonumber(session.retries)
    if not session.retries then
      return FAIL(BADRETRIES)
    elseif session.retries < 0 then
      return FAIL(BADRETRIES)
    end
  end
  
  -- agent: any or 0.0.0.0 (default)
  if not session.peer  then
    session.peer = "0.0.0.0"
  elseif type(session.peer)~="string" then
    return FAIL(BADPEER)
  end
  
  -- port: any or 161 (default)
  if not session.port then
    session.port = config.defaultPort or 161
  else
    session.port = tonumber(session.port)
    if not session.port then
      return FAIL(BADPORT)
    elseif session.port < 0 then
      return FAIL(BADPORT)
    end
  end
  
  -- default callback: 
  if session.callback then
    if type(session.callback) ~= "function" then
      return FAIL(BADCALLBACK)
    end
  end
  
  -- trap callback: 
  if session.trap then
    if type(session.trap) ~= "function" then
      return FAIL(BADTRAP)
    end
    session.usertrap = session.trap
    session.trap = __trap
  end

  -- inform callback:
  if session.inform then
    if session.version == SNMPv1 then
      return FAIL(INVINFO)
    end
    if type(session.inform) ~= "function" then
      return FAIL(BADINFO)
    end
  end

  -- walk control
  if session.includeroot then
    if session.version == SNMPv1 then
      return FAIL(INVINFO)
    end
    if type(session.includeroot) ~= "boolean" then
      return FAIL(BADINCL)
    end
  else
    session.includeroot = false
  end

  --
  -- This opens the net-snmp session
  --
  local intsess, ip_err = _open(session)
  if not intsess then return nil, ip_err end
  
  -- Informationals
  session.verid = "LuaSNMP " .. snmp.version
  session.internal = intsess
  session.peer_ip = ip_err
  session.getversion = function(self)
			 if not self then 
			   return FAIL(BADSESSION)
			 end
			 if self.version == SNMPv1 then 
			   return "SNMPv1" 
			 elseif self.version == SNMPv2c then
			   return "SNMPv2c"
			 elseif self.version == SNMPv3 then
			   return "SNMPv3"
			 else
			   return FAIL(BADSESSION)
			 end
		       end

  -- map snmp methods to the session
  session.wait = wait
  session.get = get
  session.getnext = getnext
  session.getbulk = getbulk
  session.asynch_get = asynch_get
  session.asynch_getnext = asynch_getnext
  session.asynch_getbulk = asynch_getbulk
  session.close = function(self)
     -- We need to remove the running user from library's userList.
     -- Otherwise a new session with new passowrd to the same machine (engineID) fails.
     if session.version == SNMPv3 then
        self:removeuser(rawget(self,"user"))
     end
     return close(session)
  end
  session.set = set
  session.asynch_set = asynch_set
  session.inform = inform
  session.asynch_inform = asynch_inform
  session.walk = walk
  session.newvar = function(session, name, value, type) 
		     return newvar(name, value, type, session) 
		   end
--  session.clone = clone
  session.newpassword = newpassword
  session.createuser = createuser
  session.deleteuser = deleteuser
  session.clonefromuser = clonefromuser
  session.details = details
  session.createsectogroup = createsectogroup
  session.deletesectogroup = deletesectogroup
  session.createview = createview
  session.deleteview = deleteview
  session.createaccess = createaccess
  session.deleteaccess = deleteaccess
  session.removeuser = removeuser
  -- 
  -- A cache with weak values for SNMP object type cacheing.
  --
  session.cache ={}
  setmetatable(session.cache, {__mode="v"})
  setmetatable(session, {

		 -- Syntactic sugar: val = sess.OBJECT <=> val = sess:get(OBJECT)
		 __index = function(self, key)
			     if sessionproperties[key] then
			       return sessionproperties[key](self)
			     else
			       local name = string.gsub(key, "_",".")
			       local rv, err = self:walk(name)
			       try(not err, err)
			       if #rv == 1 then
				 -- No successor and single: return scalar 
				 return rv[1].value
			       else
				 -- No successor and multiple: return list of values
				 local t = {}
				 for _,v in ipairs(rv) do
				   t[mib.name(v.oid)] = v.value
				 end
				 return t
			       end
			     end
			   end,
		 -- Syntactic sugar: sess.OBJECT = val <=> sess:set(OBJECT)
		 __newindex = function(self, key, value)
				local name = string.gsub(key, "_",".")
				-- Value is a table. Set all values - recursive.
				if type(value) == "table" then
				  for k,v in pairs(v) do
				    self[k] = v
				  end
				else
				  return try(self:set{oid=name, value=value})
				end
			      end,
		 __newindex2 = function(self, key, value)
				local name = string.gsub(key, "_",".")
				-- Value is a table. Set all values - recursive.
				if type(value) == "table" then
				  for k,v in pairs(v) do
				    self[k] = v
				  end
				end
				-- Look for an entry in the varbinding cache
				local entry = self.cache[name]
				if entry then
				  -- found one: just enter the value
				  entry.value=value
				  return try(self:set(entry))
				else
				  -- no entry found: construct a new varbinding and
				  -- put it into the cache.
				  local oid = mib.oid(name)
				  local entry = {oid=oid, type=mib.type(oid), value=value}
				  self.cache[name] = entry
				  return try(self:set(entry))
				end
			      end,
	       })
  
  -- Return the session handle
  return session
end


local _assert = _G.assert
---------------------------------------------------------------------------
-- Check result of a function.
-- The function performs an extended check on both exp == true and a nil
-- error message instead of just check the expression exp as assert does.
-- @param exp boolean - Expression to check.
-- @param err string - Error message to evaluate.
-- @return exp if (exp == true) and (err == nil), exit otherwise
---------------------------------------------------------------------------
function check(exp, err, ...)
  if exp ~= nil and not err then
    return exp
  else
    _assert(exp, err or "unknown")
  end
end

return snmp
