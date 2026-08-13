import type {
  AiFinding,
  SummaryMetric,
  TelemetrySource,
  ThreatActivityPoint,
} from "@/types/security";

export const SUMMARY_METRICS: SummaryMetric[] = [
  {
    label: "Security Events",
    value: "1,284",
    context: "+12.4% over the previous 24h",
    tone: "neutral",
  },
  {
    label: "Critical Events",
    value: "7",
    context: "3 remain unresolved",
    tone: "critical",
  },
  {
    label: "AI Flagged",
    value: "23",
    context: "8 high-confidence findings",
    tone: "warning",
  },
  {
    label: "Monitored Assets",
    value: "146",
    context: "142 currently reporting",
    tone: "positive",
  },
];

export const THREAT_ACTIVITY: ThreatActivityPoint[] = [
  { day: "Wed", critical: 2, high: 8, medium: 18, low: 26 },
  { day: "Thu", critical: 1, high: 11, medium: 21, low: 22 },
  { day: "Fri", critical: 3, high: 9, medium: 17, low: 30 },
  { day: "Sat", critical: 1, high: 6, medium: 12, low: 18 },
  { day: "Sun", critical: 2, high: 5, medium: 14, low: 20 },
  { day: "Mon", critical: 4, high: 13, medium: 24, low: 34 },
  { day: "Tue", critical: 7, high: 16, medium: 29, low: 38 },
];

export const AI_FINDINGS: AiFinding[] = [
  {
    id: "AIF-291",
    title: "Encoded command followed by credential access",
    severity: "critical",
    confidence: 96,
    affectedEntity: "WS-FIN-042 / j.morales",
    reasoning:
      "A hidden PowerShell process decoded an in-memory payload, then accessed LSASS within 41 seconds. The sequence is inconsistent with this host's baseline.",
    technique: { id: "T1059.001", name: "PowerShell" },
  },
  {
    id: "AIF-287",
    title: "Authentication failures indicate password spraying",
    severity: "high",
    confidence: 91,
    affectedEntity: "vpn-gateway-01 / 27 accounts",
    reasoning:
      "A single external source attempted one common password across multiple accounts while remaining below per-account lockout thresholds.",
    technique: { id: "T1110.003", name: "Password Spraying" },
  },
  {
    id: "AIF-284",
    title: "New outbound beaconing pattern",
    severity: "high",
    confidence: 87,
    affectedEntity: "SRV-APP-07",
    reasoning:
      "Regular 60-second TLS connections began to a newly observed autonomous system. Traffic volume is low but periodicity is strongly anomalous.",
    technique: { id: "T1071.001", name: "Web Protocols" },
  },
];

export const TELEMETRY_SOURCES: TelemetrySource[] = [
  {
    name: "Endpoint telemetry",
    status: "Healthy",
    coverage: "142 / 146 assets",
    lastEvent: "12 sec ago",
  },
  {
    name: "Authentication logs",
    status: "Healthy",
    coverage: "8 / 8 sources",
    lastEvent: "6 sec ago",
  },
  {
    name: "Network telemetry",
    status: "Delayed",
    coverage: "5 / 6 sensors",
    lastEvent: "4 min ago",
  },
];
