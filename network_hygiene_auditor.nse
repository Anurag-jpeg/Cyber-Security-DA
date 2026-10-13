local nmap   = require "nmap"
local stdnse = require "stdnse"
local table  = require "table"
local string = require "string"
local math   = require "math"

description = [[
Passive network hygiene summary. Reads only the TCP ports/services Nmap
already found (works with -sV) and reports three things: a Security
Score/Grade, an Attack-Surface Exposure summary, and a "What an Attacker
Sees" view. Sends no probes of its own.
]]

author = "Security Hygiene Auditor"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

-- (1) hostrule: Nmap has already scanned + version-detected the host by
-- the time this runs, so we can read its port table without probing.
hostrule = function(host) return true end

-- (2) Lookup tables: everything the script "knows" is plain local data.
local TELNET = { [23] = true }
local FTP    = { [21] = true }
local HTTP   = { [80] = true, [8080] = true }
local HTTPS  = { [443] = true, [8443] = true }
local SMB    = { [139] = true, [445] = true }
local DB     = { [1433]="MSSQL", [3306]="MySQL", [5432]="PostgreSQL",
                 [27017]="MongoDB", [6379]="Redis" }
local ADMIN  = { [3389]="RDP", [5900]="VNC", [22]="SSH" }
local LEGACY = { [23]=true, [21]=true, [69]=true, [161]=true }
local INTERESTING = { [25]="SMTP", [53]="DNS", [161]="SNMP", [123]="NTP" }
-- Lower number = higher priority for "likely entry point"
local ENTRY_PRIORITY = { [23]=1, [21]=2, [27017]=3, [6379]=3, [445]=4, [139]=4, [3389]=5, [5900]=5 }

-- (3) Small helper functions
local function grade_for(score)
  if score >= 90 then return "A" elseif score >= 80 then return "B"
  elseif score >= 70 then return "C" elseif score >= 60 then return "D"
  else return "F" end
end

local function bar(pct)
  local filled = math.floor(pct / 10 + 0.5)
  return "[" .. string.rep("#", filled) .. string.rep(".", 10 - filled) .. "] " .. pct .. "%"
end

-- (4) Pulls every open TCP port Nmap recorded, one at a time.
local function collect_ports(host)
  local ports = {}
  local p = nmap.get_ports(host, nil, "tcp", "open")
  while p do
    table.insert(ports, p)
    p = nmap.get_ports(host, p, "tcp", "open")
  end
  return ports
end

-- (5) Main entry point: called once per host.
action = function(host)
  local ports = collect_ports(host)
  if #ports == 0 then
    return stdnse.format_output(true, "No open TCP ports found; nothing to audit.")
  end

  -- Pass 1: do we see HTTPS anywhere? Needed to judge plain HTTP fairly.
  local has_https = false
  for _, p in ipairs(ports) do
    if HTTPS[p.number] then has_https = true end
  end

  -- Pass 2: score + classify + profile every port in a single loop.
  local score = 100
  local legacy, admin, facing = 0, 0, 0
  local hv, hv_seen = {}, {}
  local interesting, int_seen = {}, {}
  local entry_rank, entry = 99, "None identified"
  local versioned = 0

  for _, p in ipairs(ports) do
    local n = p.number

    -- Security score: subtract points for risky categories.
    if TELNET[n] then score = score - 25
    elseif FTP[n] then score = score - 15
    elseif SMB[n] then score = score - 15
    elseif DB[n] then score = score - 15
    elseif HTTP[n] and not has_https then score = score - 8
    elseif ADMIN[n] and n ~= 22 then score = score - 8
    end

    -- Exposure classification: every port falls into exactly one bucket.
    if LEGACY[n] then legacy = legacy + 1
    elseif ADMIN[n] or SMB[n] then admin = admin + 1
    else facing = facing + 1
    end

    -- Label this port if it's something an attacker would value.
    local label = (TELNET[n] and "Telnet") or (FTP[n] and "FTP") or
      (HTTP[n] and "HTTP") or (HTTPS[n] and "HTTPS") or (SMB[n] and "SMB") or
      DB[n] or (ADMIN[n] and n ~= 22 and ADMIN[n])
    if label and not hv_seen[label] then
      table.insert(hv, label); hv_seen[label] = true
    end

    -- Track lesser services worth a mention.
    if INTERESTING[n] and not int_seen[INTERESTING[n]] then
      table.insert(interesting, INTERESTING[n]); int_seen[INTERESTING[n]] = true
    end

    -- Track the single highest-priority "likely entry point".
    if ENTRY_PRIORITY[n] and ENTRY_PRIORITY[n] < entry_rank then
      entry_rank = ENTRY_PRIORITY[n]
      entry = label or ("port " .. n)
    end

    -- Count ports where -sV revealed a product/version banner.
    if p.version and ((p.version.product and p.version.product ~= "")
        or (p.version.version and p.version.version ~= "")) then
      versioned = versioned + 1
    end
  end
  if score < 0 then score = 0 end

  -- Exposure score/level from the three category counts above.
  local exposure_score = legacy * 20 + admin * 10 + facing * 3
  if exposure_score > 100 then exposure_score = 100 end
  local level = "Low"
  if legacy >= 2 or exposure_score >= 70 then level = "High"
  elseif legacy >= 1 or admin >= 2 or exposure_score >= 35 then level = "Medium"
  end

  -- Recon difficulty from how many ports leaked version info.
  local ratio = versioned / #ports
  local difficulty = "HIGH"
  if ratio >= 0.5 or #ports >= 12 then difficulty = "LOW"
  elseif ratio >= 0.2 or #ports >= 6 then difficulty = "MEDIUM"
  end

  -- (6) Build the three-section report.
  local out = {}
  table.insert(out, string.format("Security Score: %d/100  (Grade %s)", score, grade_for(score)))
  table.insert(out, "")

  local expOut = { name = "Attack Surface Exposure" }
  table.insert(expOut, bar(exposure_score))
  table.insert(expOut, "Internet Facing : " .. facing)
  table.insert(expOut, "Administrative  : " .. admin)
  table.insert(expOut, "Legacy Protocols: " .. legacy)
  table.insert(expOut, "Exposure Level  : " .. level)
  table.insert(out, expOut)

  local attOut = { name = "What an Attacker Sees" }
  table.insert(attOut, "High Value Targets : " .. (#hv > 0 and table.concat(hv, ", ") or "none"))
  table.insert(attOut, "Likely Entry Point  : " .. entry)
  table.insert(attOut, "Other Services      : " .. (#interesting > 0 and table.concat(interesting, ", ") or "none"))
  table.insert(attOut, "Recon Difficulty    : " .. difficulty)
  table.insert(out, attOut)

  return stdnse.format_output(true, out)
end
