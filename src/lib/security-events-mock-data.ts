import type { SecurityEvent } from "@/types/security";

export const SECURITY_EVENTS: SecurityEvent[] = [
  {
    id: "EVT-7842", timestamp: "2026-08-12T14:32:18-05:00", severity: "critical", category: "Execution",
    title: "Suspicious encoded PowerShell execution",
    description: "PowerShell launched with an encoded command, decoded an in-memory payload, and attempted access to a protected credential process.",
    status: "Investigating", riskScore: 96, sourceType: "EDR", asset: "WS-FIN-042", sourceIp: "10.24.18.42", user: "j.morales",
    processName: "powershell.exe", parentProcess: "winword.exe",
    commandLine: "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
    detectionRule: { id: "DET-PS-014", name: "Encoded PowerShell with suspicious parent" },
    mitreTechniques: [{ id: "T1059.001", name: "PowerShell" }, { id: "T1027", name: "Obfuscated Files or Information" }],
    relatedEventIds: ["EVT-7814", "EVT-7809"],
  },
  {
    id: "EVT-7839", timestamp: "2026-08-12T14:19:44-05:00", severity: "high", category: "Authentication",
    title: "Repeated failed authentication attempts", description: "One external address attempted authentication against 27 user accounts with a consistent password pattern.",
    status: "Open", riskScore: 88, sourceType: "Identity", asset: "vpn-gateway-01", sourceIp: "185.220.101.34", user: "multiple accounts",
    detectionRule: { id: "DET-AUTH-008", name: "Distributed account password spray" },
    mitreTechniques: [{ id: "T1110.003", name: "Password Spraying" }], relatedEventIds: ["EVT-7817"],
  },
  {
    id: "EVT-7835", timestamp: "2026-08-12T13:57:06-05:00", severity: "high", category: "Network",
    title: "Unusual outbound traffic to rare destination", description: "A production application server began periodic TLS connections to a destination not previously observed in the environment.",
    status: "Investigating", riskScore: 84, sourceType: "Network Sensor", asset: "SRV-APP-07", sourceIp: "10.20.7.18", destinationIp: "45.77.214.62",
    processName: "svchost.exe", detectionRule: { id: "DET-NET-021", name: "Rare destination with beaconing periodicity" },
    mitreTechniques: [{ id: "T1071.001", name: "Web Protocols" }], relatedEventIds: ["EVT-7798"],
  },
  {
    id: "EVT-7828", timestamp: "2026-08-12T13:21:50-05:00", severity: "medium", category: "Privilege Escalation",
    title: "Privilege escalation behavior detected", description: "A standard user process attempted to create and start a service with local system privileges.",
    status: "Contained", riskScore: 72, sourceType: "Endpoint", asset: "LT-ENG-118", user: "r.chen", processName: "sc.exe", parentProcess: "cmd.exe",
    commandLine: "sc.exe create WinUpdateHelper binPath= C:\\Users\\Public\\update.exe start= auto",
    detectionRule: { id: "DET-PRIV-006", name: "Service creation by non-administrative user" }, mitreTechniques: [{ id: "T1543.003", name: "Windows Service" }],
  },
  {
    id: "EVT-7821", timestamp: "2026-08-12T12:48:12-05:00", severity: "medium", category: "Malware",
    title: "Endpoint malware detection quarantined", description: "EDR identified and quarantined a trojanized archive attachment before execution.",
    status: "Contained", riskScore: 68, sourceType: "EDR", asset: "WS-HR-016", user: "a.patel", processName: "outlook.exe",
    detectionRule: { id: "DET-MAL-031", name: "Known malicious archive signature" },
  },
  {
    id: "EVT-7817", timestamp: "2026-08-12T12:26:03-05:00", severity: "medium", category: "Authentication",
    title: "Account lockout activity across privileged users", description: "Four privileged accounts were locked within seven minutes following authentication attempts from the VPN gateway.",
    status: "Open", riskScore: 74, sourceType: "Identity", asset: "DC-CORP-02", sourceIp: "185.220.101.34", user: "privileged account group",
    detectionRule: { id: "DET-AUTH-012", name: "Correlated privileged account lockouts" }, relatedEventIds: ["EVT-7839"],
  },
  {
    id: "EVT-7814", timestamp: "2026-08-12T11:54:29-05:00", severity: "high", category: "Execution",
    title: "Suspicious process ancestry", description: "Microsoft Word spawned a command shell that immediately launched a hidden PowerShell process.",
    status: "Investigating", riskScore: 86, sourceType: "EDR", asset: "WS-FIN-042", user: "j.morales", processName: "cmd.exe", parentProcess: "winword.exe",
    commandLine: "cmd.exe /c powershell -w hidden -nop -e SQBFAFgA",
    detectionRule: { id: "DET-PROC-019", name: "Office application spawning command interpreter" },
    mitreTechniques: [{ id: "T1204.002", name: "Malicious File" }], relatedEventIds: ["EVT-7842", "EVT-7809"],
  },
  {
    id: "EVT-7809", timestamp: "2026-08-12T11:49:11-05:00", severity: "high", category: "Persistence",
    title: "Registry run key modification", description: "A newly created executable was added to the current user's Run key shortly after a suspicious document opened.",
    status: "Open", riskScore: 82, sourceType: "Endpoint", asset: "WS-FIN-042", user: "j.morales", processName: "reg.exe", parentProcess: "powershell.exe",
    commandLine: "reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v UpdateCheck /d C:\\Users\\Public\\update.exe",
    detectionRule: { id: "DET-PERS-004", name: "New executable registered for logon persistence" },
    mitreTechniques: [{ id: "T1060", name: "Registry Run Keys / Startup Folder" }], relatedEventIds: ["EVT-7842", "EVT-7814"],
  },
  {
    id: "EVT-7803", timestamp: "2026-08-12T10:58:37-05:00", severity: "medium", category: "Discovery",
    title: "Network scanning behavior", description: "A workstation contacted 94 internal hosts across common administrative ports within two minutes.",
    status: "Open", riskScore: 70, sourceType: "Network Sensor", asset: "LT-SALES-033", sourceIp: "10.32.4.33",
    detectionRule: { id: "DET-DISC-011", name: "Internal horizontal port scan" }, mitreTechniques: [{ id: "T1046", name: "Network Service Discovery" }],
  },
  {
    id: "EVT-7798", timestamp: "2026-08-12T10:21:15-05:00", severity: "medium", category: "Network",
    title: "DNS requests to newly registered domain", description: "A server queried a domain registered within the last 24 hours and then established an encrypted outbound connection.",
    status: "Investigating", riskScore: 76, sourceType: "Network Sensor", asset: "SRV-APP-07", sourceIp: "10.20.7.18", destinationIp: "45.77.214.62",
    detectionRule: { id: "DET-DNS-017", name: "Newly registered domain from server segment" }, relatedEventIds: ["EVT-7835"],
  },
  {
    id: "EVT-7791", timestamp: "2026-08-12T09:46:52-05:00", severity: "low", category: "Authentication",
    title: "Successful login from new device", description: "A user authenticated successfully from a managed device not previously associated with the account.",
    status: "Resolved", riskScore: 34, sourceType: "Identity", asset: "LT-MKT-087", sourceIp: "10.31.8.87", user: "s.williams",
    detectionRule: { id: "DET-AUTH-003", name: "First-seen device for user" },
  },
  {
    id: "EVT-7786", timestamp: "2026-08-12T09:12:08-05:00", severity: "low", category: "Malware",
    title: "Potentially unwanted application blocked", description: "Endpoint protection blocked an unsigned browser extension installer downloaded from an advertising redirect.",
    status: "Resolved", riskScore: 29, sourceType: "EDR", asset: "WS-OPS-024", user: "k.nguyen", processName: "chrome.exe",
    detectionRule: { id: "DET-MAL-009", name: "Potentially unwanted application" },
  },
  {
    id: "EVT-7779", timestamp: "2026-08-12T08:37:40-05:00", severity: "high", category: "Privilege Escalation",
    title: "Unexpected addition to Domain Admins", description: "A service account added a user to the Domain Admins group outside the approved change window.",
    status: "Contained", riskScore: 89, sourceType: "Identity", asset: "DC-CORP-01", sourceIp: "10.10.1.12", user: "svc_deploy",
    detectionRule: { id: "DET-PRIV-002", name: "Domain Admins membership changed" }, mitreTechniques: [{ id: "T1098", name: "Account Manipulation" }],
  },
  {
    id: "EVT-7772", timestamp: "2026-08-12T07:59:26-05:00", severity: "medium", category: "Network",
    title: "Inbound connection blocked from threat-listed IP", description: "The perimeter firewall blocked repeated connection attempts to the remote administration interface.",
    status: "Resolved", riskScore: 61, sourceType: "Firewall", asset: "fw-edge-01", sourceIp: "91.215.85.17", destinationIp: "203.0.113.18",
    detectionRule: { id: "DET-FW-026", name: "Threat intelligence source match" },
  },
  {
    id: "EVT-7764", timestamp: "2026-08-12T07:14:03-05:00", severity: "low", category: "Discovery",
    title: "Administrative share enumeration", description: "A management workstation enumerated administrative shares on six servers during an approved maintenance window.",
    status: "Resolved", riskScore: 25, sourceType: "Endpoint", asset: "PAW-ADMIN-03", user: "m.jackson", processName: "net.exe", parentProcess: "powershell.exe",
    commandLine: "net.exe view \\SRV-FILE-02 /all", detectionRule: { id: "DET-DISC-005", name: "Remote share discovery" }, mitreTechniques: [{ id: "T1135", name: "Network Share Discovery" }],
  },
];

export function getSecurityEvent(eventId: string) {
  return SECURITY_EVENTS.find((event) => event.id.toLowerCase() === eventId.toLowerCase());
}
