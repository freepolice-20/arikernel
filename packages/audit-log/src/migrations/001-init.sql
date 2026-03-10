CREATE TABLE IF NOT EXISTS runs (
  run_id        TEXT PRIMARY KEY,
  principal_id  TEXT NOT NULL,
  started_at    TEXT NOT NULL,
  ended_at      TEXT,
  event_count   INTEGER DEFAULT 0,
  config_json   TEXT NOT NULL,
  start_previous_hash TEXT
);

CREATE TABLE IF NOT EXISTS events (
  id            TEXT PRIMARY KEY,
  run_id        TEXT NOT NULL REFERENCES runs(run_id),
  sequence      INTEGER NOT NULL,
  timestamp     TEXT NOT NULL,
  principal_id  TEXT NOT NULL,
  tool_class    TEXT NOT NULL,
  action        TEXT NOT NULL,
  tool_call_json TEXT NOT NULL,
  decision_json  TEXT NOT NULL,
  result_json    TEXT,
  duration_ms    INTEGER,
  taint_sources  TEXT NOT NULL,
  verdict        TEXT NOT NULL,
  previous_hash  TEXT NOT NULL,
  hash           TEXT NOT NULL,
  UNIQUE(run_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, sequence);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict);
CREATE INDEX IF NOT EXISTS idx_events_tool ON events(tool_class, action);
