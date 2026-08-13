import "server-only";

import type {
  ApiDetection,
  ApiSecurityEvent,
  ApiSecurityEventDetail,
  SecurityEventListItem,
} from "@/types/siberai-api";

const API_REQUEST_TIMEOUT_MS = 5000;

function apiUrl() {
  return (process.env.SIBERAI_API_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");
}

export class SiberAiApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "SiberAiApiError";
  }
}

function isAbortError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  if (error.name === "AbortError") return true;
  return "cause" in error && isAbortError(error.cause);
}

async function apiFetch<T>(path: string): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), API_REQUEST_TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(`${apiUrl()}${path}`, {
      cache: "no-store",
      signal: controller.signal,
    });
  } catch (error) {
    // Next.js cancels in-flight Server Component work when a client navigation
    // supersedes it. Let that cancellation reach the router so it can discard
    // the render instead of caching an incorrect API-unavailable result.
    if (isAbortError(error) && !controller.signal.aborted) throw error;
    throw new SiberAiApiError("The SiberAI engine API could not be reached.");
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    throw new SiberAiApiError(`SiberAI API request failed with status ${response.status}.`, response.status);
  }
  return response.json() as Promise<T>;
}

export async function getSecurityEvents(limit = 100): Promise<SecurityEventListItem[]> {
  const boundedLimit = Math.min(Math.max(limit, 1), 200);
  const [events, detections] = await Promise.all([
    apiFetch<ApiSecurityEvent[]>(`/api/events?limit=${boundedLimit}`),
    apiFetch<ApiDetection[]>(`/api/detections?limit=${boundedLimit}`),
  ]);
  const detectionsByEvent = new Map<string, ApiDetection[]>();
  for (const detection of detections) {
    const existing = detectionsByEvent.get(detection.event_id) ?? [];
    existing.push(detection);
    detectionsByEvent.set(detection.event_id, existing);
  }
  return events.map((event) => ({ ...event, detections: detectionsByEvent.get(event.event_id) ?? [] }));
}

export async function getSecurityEvent(eventId: string): Promise<ApiSecurityEventDetail | null> {
  let decodedEventId = eventId;
  try {
    decodedEventId = decodeURIComponent(eventId);
  } catch {
    // Keep the original value; the API will return a normal not-found response.
  }
  try {
    return await apiFetch<ApiSecurityEventDetail>(`/api/events/${encodeURIComponent(decodedEventId)}`);
  } catch (error) {
    if (error instanceof SiberAiApiError && error.status === 404) return null;
    throw error;
  }
}
