export type ApiSeverity = "low" | "medium" | "high" | "critical";

export interface ApiDetection {
  detection_id: string;
  event_id: string;
  rule_id: string;
  title: string;
  severity: ApiSeverity;
  risk_score: number;
  description: string;
  mitre_techniques: string[];
  evidence: Record<string, unknown>;
  created_at: string;
  event_timestamp: string | null;
  host: string | null;
  process: string | null;
}

export interface ApiSecurityEvent {
  event_id: string;
  record_id: number | null;
  timestamp: string;
  source_type: string;
  category: string;
  host: string | null;
  user: string | null;
  process: string | null;
  parent_process: string | null;
  command_line: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  process_guid: string | null;
  process_id: number | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  initiated: boolean | null;
  source_hostname: string | null;
  destination_hostname: string | null;
}

export interface ApiSecurityEventDetail extends ApiSecurityEvent {
  raw: Record<string, unknown> | null;
  detections: ApiDetection[];
}

export interface SecurityEventListItem extends ApiSecurityEvent {
  detections: ApiDetection[];
}
