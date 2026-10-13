description = [[
Network Role Identifier

Identifies the likely role of a host based on the
TCP services discovered by Nmap.

Author: Your Name
License: Same as Nmap
Categories: discovery, safe
]]

author = "Your Name"
license = "Same as Nmap"
categories = {"discovery", "safe"}

local nmap = require "nmap"
local stdnse = require "stdnse"

-- Fallback names for well-known ports, used only when Nmap didn't
-- attach service info to the port for some reason (e.g. no -sV, or a
-- guessed/unconfirmed match that came back empty). This is what keeps
-- the "Detected Open Ports" list from just saying "unknown" for common,
-- easily-recognized ports.
local COMMON_SERVICE_NAMES = {
    [21] = "ftp", [22] = "ssh", [23] = "telnet", [25] = "smtp",
    [53] = "dns", [80] = "http", [110] = "pop3", [135] = "msrpc",
    [139] = "netbios-ssn", [143] = "imap", [443] = "https",
    [445] = "microsoft-ds", [3306] = "mysql", [3389] = "rdp",
    [5060] = "sip", [5432] = "postgresql", [5900] = "vnc",
}

local function service_name(port)
    if port.service and port.service.name and port.service.name ~= "" then
        return port.service.name
    end
    if port.version and port.version.name and port.version.name ~= "" then
        return port.version.name
    end
    return COMMON_SERVICE_NAMES[port.number] or "unknown"
end

-- Run once after Nmap has finished scanning the host
hostrule = function(host)
    return true
end

action = function(host)

    -- FIX 1: host.ports is not a reliably documented way to get the port
    -- list (it can be nil, causing the whole script to silently return
    -- nothing). nmap.get_ports() is the documented cursor iterator: pass
    -- nil to get the first open TCP port, then feed the previous result
    -- back in to get the next one, until it returns nil.
    local ports = {}
    local p = nmap.get_ports(host, nil, "tcp", "open")
    while p do
        table.insert(ports, p)
        p = nmap.get_ports(host, p, "tcp", "open")
    end

    if #ports == 0 then
        return stdnse.format_output(true, "No open TCP ports found for this host.")
    end

    local open_ports = {}

    for _, port in ipairs(ports) do
        open_ports[port.number] = true
    end

    local role = "Unknown Device"
    local confidence = "Low"

    if open_ports[80] or open_ports[443] then
        if open_ports[22] then
            role = "Linux Web Server"
            confidence = "90%"
        else
            role = "Web Server"
            confidence = "85%"
        end

    elseif open_ports[25] and (open_ports[110] or open_ports[143]) then
        role = "Mail Server"
        confidence = "95%"

    elseif open_ports[53] then
        role = "DNS Server"
        confidence = "90%"

    elseif open_ports[3306] or open_ports[5432] then
        role = "Database Server"
        confidence = "90%"

    elseif open_ports[445] and open_ports[3389] then
        role = "Windows Workstation / Server"
        confidence = "95%"

    -- NEW: classic Windows RPC/SMB signature (135 + 445) without RDP --
    -- very common on Windows hosts/VMs that aren't set up for remote
    -- desktop, so this deserves its own rule rather than falling
    -- through to "Unknown Device".
    elseif open_ports[135] and open_ports[445] then
        role = "Windows Host (RPC/SMB)"
        confidence = "75%"

    elseif open_ports[21] then
        role = "FTP Server"
        confidence = "80%"

    elseif open_ports[5060] then
        role = "VoIP Server"
        confidence = "85%"

    elseif open_ports[3389] then
        role = "Windows Remote Desktop Host"
        confidence = "70%"

    elseif open_ports[5900] then
        role = "VNC Remote Desktop Host"
        confidence = "70%"

    -- NEW: SMB or RPC alone, weaker signal than the combo rule above,
    -- but still a much better guess than "Unknown Device".
    elseif open_ports[445] or open_ports[139] then
        role = "Windows Host (SMB)"
        confidence = "60%"

    elseif open_ports[135] then
        role = "Windows Host (RPC)"
        confidence = "55%"

    elseif open_ports[22] then
        role = "Linux / Unix Host"
        confidence = "60%"
    end

    local output = {}

    table.insert(output,"===================================")
    table.insert(output," Network Role Identifier")
    table.insert(output,"===================================")
    table.insert(output,"Host : "..host.ip)
    table.insert(output,"")
    table.insert(output,"Likely Device Role : "..role)
    table.insert(output,"Confidence         : "..confidence)
    table.insert(output,"")
    table.insert(output,"Detected Open Ports")

    for _, port in ipairs(ports) do
        table.insert(output,
            string.format("%5d/tcp  %s", port.number, service_name(port)))
    end

    return stdnse.format_output(true, output)

end
