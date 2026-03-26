#include "titan_pch.h"
#include "applog_decoder.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <regex>
#include <sstream>

// =============================================================================
// AppLogDecoder
//
// FIXES FROM ORIGINAL:
//   1. Decode() now accepts timestamp — appears in every JSON output
//   2. severity field REMOVED from JSON output and DecodedEvent
//   3. Deep content reading: URLs, encoded commands, injection flags, etc.
//   4. std::transform tolower fixed — explicit cast avoids C4244 warning
//   5. script_content shows FULL content, not 80-char truncation
//   6. Pattern list expanded to 40+ entries across 9 attack categories
// =============================================================================

AppLogDecoder::AppLogDecoder()
{
    m_suspiciousPatterns = {
        // Execution
        "invoke-expression",    "iex(",             "invoke-command",
        "start-process",        "invoke-item",       "shellexecute",
        // Download / C2
        "downloadstring",       "downloadfile",      "net.webclient",
        "webrequest",           "invoke-webrequest", "bitsadmin",
        "certutil",             "curl ",             "wget ",
        // Encoding / obfuscation
        "-encodedcommand",      "frombase64string",  "[char]",
        "join-string",
        // Memory injection
        "virtualalloc",         "createthread",      "writeprocessmemory",
        "reflection.assembly",  "load(",
        // Credential access
        "mimikatz",             "invoke-mimikatz",   "sekurlsa",
        "lsadump",              "dpapi",
        "get-credential",       "securestring",
        // Defense evasion
        "amsiutils",            "set-mppreference",  "add-mppreference",
        "bypass",               "set-executionpolicy",
        "unblock-file",         "unrestricted",
        // Persistence
        "new-scheduledtask",    "register-scheduledtask",
        "hkcu:\\software\\microsoft\\windows\\currentversion\\run",
        "new-service",
        // Recon
        "get-localuser",        "get-aduser",        "net user",
        "whoami",               "systeminfo",        "netstat",
        // Lateral movement
        "invoke-psremoting",    "new-pssession",
        "wmiobject",            "invoke-wmimethod",
    };

    std::cout << "[Decoder] Initialized with "
        << m_suspiciousPatterns.size()
        << " detection patterns.\n";
}

// =============================================================================
// Decode — main entry point, now accepts timestamp
// =============================================================================

std::string AppLogDecoder::Decode(
    const std::string& source,
    const std::string& rawData,
    const std::string& timestamp)
{
    DecodedEvent evt;

    if (source == "PowerShell" || source == "PowerShell_Fallback")
        evt = DecodePowerShell(rawData);
    else if (source == "WMI" || source == "WMI_Fallback")
        evt = DecodeWmi(rawData);
    else if (source == "WindowsDefender")
        evt = DecodeDefender(rawData);
    else if (source == "Security")
        evt = DecodeSecurity(rawData);
    else
        evt = DecodeWatchlist(source, rawData);

    // Stamp with real timestamp from event header
    evt.timestamp = timestamp;

    return BuildJson(evt);
}

// =============================================================================
// PowerShell — full deep extraction
// =============================================================================

DecodedEvent AppLogDecoder::DecodePowerShell(const std::string& raw)
{
    DecodedEvent evt;
    evt.source = "PowerShell";
    evt.event_id = "4104";

    // Extract script block text
    std::string script = ExtractXmlData(raw, "ScriptBlockText");
    if (script.empty()) script = ExtractXmlField(raw, "ScriptBlockText");
    if (script.empty()) script = raw;

    // Extract script path
    evt.script_path = ExtractXmlData(raw, "Path");

    // De-obfuscate
    evt.script_content = StripObfuscation(script);

    // Lowercase copy for pattern matching
    std::string lower = ToLower(evt.script_content);

    // Pattern hit count
    evt.pattern_hits = CountPatternHits(lower);

    // Detect and decode -EncodedCommand
    evt.encoded_decoded = DetectEncodedCommand(evt.script_content);

    // Extract network URLs
    if (lower.find("http") != std::string::npos ||
        lower.find("downloadstr") != std::string::npos ||
        lower.find("webrequest") != std::string::npos ||
        lower.find("webclient") != std::string::npos)
    {
        evt.network_activity = ExtractUrls(evt.script_content);
    }

    // Credential access flag
    evt.credential_access =
        lower.find("credential") != std::string::npos ||
        lower.find("securestring") != std::string::npos ||
        lower.find("mimikatz") != std::string::npos ||
        lower.find("sekurlsa") != std::string::npos ||
        lower.find("lsadump") != std::string::npos;

    // AMSI bypass flag
    evt.amsi_bypass =
        lower.find("amsiutils") != std::string::npos ||
        lower.find("amsicontext") != std::string::npos ||
        lower.find("amsinit") != std::string::npos ||
        lower.find("set-mppreference") != std::string::npos;

    // Process injection flag
    evt.process_injection =
        lower.find("virtualalloc") != std::string::npos ||
        lower.find("writeprocessmemory") != std::string::npos ||
        lower.find("createthread") != std::string::npos ||
        lower.find("reflection.assembly") != std::string::npos;

    // Build summary — show first 120 chars, collapse newlines
    std::string preview = evt.script_content.substr(
        0, std::min<size_t>(120, evt.script_content.size()));
    for (char& c : preview)
        if (c == '\n' || c == '\r') c = ' ';

    evt.summary = "Script: " + preview;
    if (evt.script_content.size() > 120) evt.summary += "...";

    return evt;
}

// =============================================================================
// WMI — full deep extraction
// =============================================================================

DecodedEvent AppLogDecoder::DecodeWmi(const std::string& raw)
{
    DecodedEvent evt;
    evt.source = "WMI";
    evt.event_id = ExtractXmlField(raw, "EventID");

    std::string consumer = ExtractXmlData(raw, "CONSUMER");
    std::string filter = ExtractXmlData(raw, "FILTER");
    std::string operation = ExtractXmlData(raw, "Operation");
    std::string query = ExtractXmlData(raw, "Query");
    std::string user = ExtractXmlData(raw, "User");
    std::string namesp = ExtractXmlData(raw, "NamespaceName");

    // Build full content
    std::ostringstream content;
    if (!query.empty())     content << "Query: " << query << "\n";
    if (!consumer.empty())  content << "Consumer: " << consumer << "\n";
    if (!filter.empty())    content << "Filter: " << filter << "\n";
    if (!operation.empty()) content << "Operation: " << operation << "\n";
    if (!namesp.empty())    content << "Namespace: " << namesp << "\n";
    if (!user.empty())      content << "User: " << user << "\n";
    evt.script_content = content.str();

    if (!consumer.empty() && !filter.empty())
        evt.summary = "WMI persistence binding — Consumer: "
        + consumer + " | Filter: " + filter;
    else if (!query.empty())
        evt.summary = "WMI query: "
        + query.substr(0, std::min<size_t>(100, query.size()));
    else
        evt.summary = "WMI operation: " + operation;

    // Detect suspicious process creation via WMI
    std::string lower = ToLower(evt.script_content);
    evt.process_injection =
        lower.find("win32_process") != std::string::npos &&
        (lower.find("create") != std::string::npos ||
            lower.find("cmd") != std::string::npos);

    return evt;
}

// =============================================================================
// Defender — full deep extraction
// =============================================================================

DecodedEvent AppLogDecoder::DecodeDefender(const std::string& raw)
{
    DecodedEvent evt;
    evt.source = "WindowsDefender";
    evt.event_id = "1116";

    std::string threatName = ExtractXmlData(raw, "Threat Name");
    if (threatName.empty()) threatName = ExtractXmlData(raw, "ThreatName");

    std::string path = ExtractXmlData(raw, "Path");
    std::string action = ExtractXmlData(raw, "Action");
    std::string category = ExtractXmlData(raw, "Category");
    std::string processName = ExtractXmlData(raw, "Process Name");
    std::string origin = ExtractXmlData(raw, "Origin");
    std::string user = ExtractXmlData(raw, "Detection User");

    std::ostringstream content;
    if (!threatName.empty())  content << "Threat: " << threatName << "\n";
    if (!path.empty())        content << "Path: " << path << "\n";
    if (!action.empty())      content << "Action: " << action << "\n";
    if (!category.empty())    content << "Category: " << category << "\n";
    if (!processName.empty()) content << "Process: " << processName << "\n";
    if (!origin.empty())      content << "Origin: " << origin << "\n";
    if (!user.empty())        content << "User: " << user << "\n";
    evt.script_content = content.str();

    evt.summary = "Defender: [" + threatName + "] at " + path
        + " | Action: " + action;

    return evt;
}

// =============================================================================
// Security — full deep extraction
// =============================================================================

DecodedEvent AppLogDecoder::DecodeSecurity(const std::string& raw)
{
    DecodedEvent evt;
    evt.source = "Security";

    std::string eventId = ExtractXmlField(raw, "EventID");
    std::string account = ExtractXmlData(raw, "TargetUserName");
    std::string domain = ExtractXmlData(raw, "TargetDomainName");
    std::string logonType = ExtractXmlData(raw, "LogonType");
    std::string srcIp = ExtractXmlData(raw, "IpAddress");
    std::string srcPort = ExtractXmlData(raw, "IpPort");
    std::string privileges = ExtractXmlData(raw, "PrivilegeList");
    std::string process = ExtractXmlData(raw, "ProcessName");
    std::string subStatus = ExtractXmlData(raw, "SubStatus");
    std::string workstation = ExtractXmlData(raw, "WorkstationName");

    evt.event_id = eventId;

    std::ostringstream content;
    if (!account.empty())     content << "Account: " << account << "\n";
    if (!domain.empty())      content << "Domain: " << domain << "\n";
    if (!logonType.empty())   content << "LogonType: " << logonType << "\n";
    if (!srcIp.empty())       content << "SourceIP: " << srcIp << "\n";
    if (!srcPort.empty())     content << "SourcePort: " << srcPort << "\n";
    if (!process.empty())     content << "Process: " << process << "\n";
    if (!privileges.empty())  content << "Privileges: " << privileges << "\n";
    if (!subStatus.empty())   content << "SubStatus: " << subStatus << "\n";
    if (!workstation.empty()) content << "Workstation: " << workstation << "\n";
    evt.script_content = content.str();

    if (eventId == "4625")
        evt.summary = "FAILED LOGON — Account: " + account
        + " | Type: " + logonType
        + " | From: " + srcIp;
    else if (eventId == "4672")
        evt.summary = "PRIVILEGE ESCALATION — Account: " + account
        + " | Privileges: "
        + privileges.substr(0, std::min<size_t>(80, privileges.size()));
    else if (eventId == "4688")
        evt.summary = "PROCESS CREATED — " + process
        + " | Account: " + account;
    else
        evt.summary = "Security event " + eventId
        + " — Account: " + account;

    return evt;
}

// =============================================================================
// Watchlist / generic
// =============================================================================

DecodedEvent AppLogDecoder::DecodeWatchlist(
    const std::string& source,
    const std::string& raw)
{
    DecodedEvent evt;
    evt.source = source;
    evt.event_id = ExtractXmlField(raw, "EventID");

    std::string msg = ExtractXmlData(raw, "Message");
    if (msg.empty()) msg = ExtractXmlData(raw, "Description");
    if (msg.empty() && raw.size() > 0)
        msg = raw.substr(0, std::min<size_t>(200, raw.size()));

    evt.script_content = msg;
    evt.summary = source.empty()
        ? "Unknown event"
        : "Event from " + source + " | ID: " + evt.event_id;

    return evt;
}

// =============================================================================
// Pattern counting
// =============================================================================

int AppLogDecoder::CountPatternHits(const std::string& lower) const
{
    int hits = 0;
    for (const auto& p : m_suspiciousPatterns)
        if (lower.find(p) != std::string::npos)
            ++hits;
    return hits;
}

// =============================================================================
// Encoded command detection + base64 decode
// =============================================================================

std::string AppLogDecoder::DetectEncodedCommand(
    const std::string& script) const
{
    // Find -EncodedCommand / -enc / -e followed by base64 blob
    static const std::regex encRe(
        R"((?:-encodedcommand|-enc|-e)\s+([A-Za-z0-9+/]{20,}={0,2}))",
        std::regex::icase | std::regex::optimize);

    std::smatch m;
    if (!std::regex_search(script, m, encRe)) return "";

    std::string b64 = m[1].str();

    // Base64 decode (PowerShell uses UTF-16LE — skip null bytes)
    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string decoded;
    int val = 0, bits = -8;
    for (unsigned char c : b64) {
        auto pos = chars.find(static_cast<char>(c));
        if (pos == std::string::npos) continue;
        val = (val << 6) + static_cast<int>(pos);
        bits += 6;
        if (bits >= 0) {
            char ch = static_cast<char>((val >> bits) & 0xFF);
            if (ch != '\0') decoded += ch;  // skip UTF-16 null bytes
            bits -= 8;
        }
    }
    return decoded.empty() ? b64 : decoded;
}

// =============================================================================
// URL extraction
// =============================================================================

std::string AppLogDecoder::ExtractUrls(const std::string& script) const
{
    static const std::regex urlRe(
        R"(https?://[^\s"'<>\]]+)",
        std::regex::optimize);

    std::string result;
    auto it = std::sregex_iterator(script.begin(), script.end(), urlRe);
    auto end = std::sregex_iterator();
    for (; it != end; ++it) {
        if (!result.empty()) result += " | ";
        result += it->str();
    }
    return result;
}

// =============================================================================
// De-obfuscation
// =============================================================================

std::string AppLogDecoder::StripObfuscation(const std::string& script)
{
    if (script.empty()) return "";

    std::string result = script;

    // Remove backtick escapes
    result.erase(
        std::remove(result.begin(), result.end(), '`'),
        result.end());

    // Mark long base64 blobs
    static const std::regex b64Re(
        R"([A-Za-z0-9+/]{40,}={0,2})",
        std::regex::optimize);
    result = std::regex_replace(result, b64Re, "[BASE64_BLOB]");

    // Collapse string concatenation
    static const std::regex concatRe(
        R"DELIM("([^"]+)"\s*\+\s*"([^"]+)")DELIM",
        std::regex::optimize);
    for (int i = 0; i < 3; ++i)
        result = std::regex_replace(result, concatRe, "\"$1$2\"");

    return result;
}

// =============================================================================
// JSON builder — NO severity field
// =============================================================================

std::string AppLogDecoder::BuildJson(const DecodedEvent& evt)
{
    std::ostringstream j;
    j << "{\n"
        << "  \"source\": \"" << JsonEscape(evt.source) << "\",\n"
        << "  \"event_id\": \"" << JsonEscape(evt.event_id) << "\",\n"
        << "  \"timestamp\": \"" << JsonEscape(evt.timestamp) << "\",\n"
        << "  \"summary\": \"" << JsonEscape(evt.summary) << "\",\n"
        << "  \"script_content\": \"" << JsonEscape(evt.script_content) << "\",\n"
        << "  \"script_path\": \"" << JsonEscape(evt.script_path) << "\",\n"
        << "  \"encoded_decoded\": \"" << JsonEscape(evt.encoded_decoded) << "\",\n"
        << "  \"network_activity\": \"" << JsonEscape(evt.network_activity) << "\",\n"
        << "  \"pattern_hits\": " << evt.pattern_hits << ",\n"
        << "  \"credential_access\": " << (evt.credential_access ? "true" : "false") << ",\n"
        << "  \"amsi_bypass\": " << (evt.amsi_bypass ? "true" : "false") << ",\n"
        << "  \"process_injection\": " << (evt.process_injection ? "true" : "false") << "\n"
        << "}";
    return j.str();
}

// =============================================================================
// XML helpers
// =============================================================================

std::string AppLogDecoder::ExtractXmlField(
    const std::string& xml, const std::string& tag)
{
    std::string open = "<" + tag + ">";
    std::string close = "</" + tag + ">";
    auto start = xml.find(open);
    if (start == std::string::npos) return "";
    start += open.size();
    auto end = xml.find(close, start);
    if (end == std::string::npos) return "";
    return xml.substr(start, end - start);
}

std::string AppLogDecoder::ExtractXmlData(
    const std::string& xml, const std::string& name)
{
    std::string open = "<Data Name=\"" + name + "\">";
    std::string close = "</Data>";
    auto start = xml.find(open);
    if (start == std::string::npos) return "";
    start += open.size();
    auto end = xml.find(close, start);
    if (end == std::string::npos) return "";
    return xml.substr(start, end - start);
}

// =============================================================================
// Helpers
// =============================================================================

std::string AppLogDecoder::ToLower(const std::string& s)
{
    std::string r = s;
    // FIXED: explicit cast to unsigned char then to char — no C4244 warning
    std::transform(r.begin(), r.end(), r.begin(),
        [](unsigned char c) -> char {
            return static_cast<char>(std::tolower(c));
        });
    return r;
}

std::string AppLogDecoder::JsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            }
            else {
                out += static_cast<char>(c);
            }
        }
    }
    return out;
}