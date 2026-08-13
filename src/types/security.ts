export type Severity = "critical" | "high" | "medium" | "low";

export type EventStatus = "Open" | "Investigating" | "Contained" | "Resolved";

export type EventCategory =
  | "Execution"
  | "Authentication"
  | "Network"
  | "Privilege Escalation"
  | "Malware"
  | "Persistence"
  | "Discovery";

export type EventSourceType =
  | "Endpoint"
  | "Identity"
  | "Network Sensor"
  | "Firewall"
  | "EDR";

export interface MitreTechnique {
  id: string;
  name: string;
}

export interface SummaryMetric {
  label: string;
  value: string;
  context: string;
  tone: "neutral" | "critical" | "warning" | "positive";
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  severity: Severity;
  category: EventCategory;
  title: string;
  description: string;
  status: EventStatus;
  riskScore: number;
  sourceType: EventSourceType;
  asset?: string;
  sourceIp?: string;
  destinationIp?: string;
  user?: string;
  processName?: string;
  parentProcess?: string;
  commandLine?: string;
  detectionRule: {
    id: string;
    name: string;
  };
  mitreTechniques?: MitreTechnique[];
  relatedEventIds?: string[];
}

export interface ThreatActivityPoint {
  day: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface AiFinding {
  id: string;
  title: string;
  severity: Severity;
  confidence: number;
  affectedEntity: string;
  reasoning: string;
  technique?: MitreTechnique;
}

export type TelemetryStatus = "Healthy" | "Delayed" | "Degraded";

export interface TelemetrySource {
  name: string;
  status: TelemetryStatus;
  coverage: string;
  lastEvent: string;
}
