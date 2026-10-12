// #region relay-log — docs: docs/adr/0002-estate-hub.md
// One log line shape for both builds: `{at, service: "relay", runtime, event, …}`, one JSON object per line. A line
// never carries a request body, a token or an envelope (AGENTS.md, Local rules); callers pass names and counts.

import { SERVICE, type Runtime } from "./relay.ts";

export type Log = (event: Record<string, unknown>) => void;

export function jsonLog(runtime: Runtime, write: (line: string) => void = (line) => console.log(line), now: () => Date = () => new Date()): Log {
  return (event) => write(JSON.stringify({ at: now().toISOString(), service: SERVICE, runtime, ...event }));
}

/** An error as a log line may carry it: its name and the first 200 characters of its message. */
export function errorFields(error: unknown): { error: string; message: string } {
  return { error: (error as Error)?.name ?? "Error", message: String((error as Error)?.message ?? error).slice(0, 200) };
}
// #endregion relay-log
