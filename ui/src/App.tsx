import { useMemo, useState } from "react";

import "./app.css";

const severities = ["critical", "high", "medium", "low"] as const;
type Severity = (typeof severities)[number];

type Remediation = { kind: string; summary: string; suggested?: string[] };
type Finding = {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  steps?: string[];
  score: number;
  target: string;
  target_name?: string;
  evidence?: Record<string, unknown>;
  remediation: Remediation;
};
type Findings = {
  schema_version: string;
  generated_at?: string;
  findings: Finding[];
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((item) => typeof item === "string")
  );
}

export function validateFindings(value: unknown): Findings {
  if (
    !isRecord(value) ||
    typeof value.schema_version !== "string" ||
    !value.schema_version.startsWith("1.")
  ) {
    throw new Error("Unsupported or missing findings schema version.");
  }
  if (!Array.isArray(value.findings)) {
    throw new Error("The file must contain a findings array.");
  }
  const findings = value.findings.map((candidate, index): Finding => {
    if (!isRecord(candidate)) {
      throw new Error(`Finding ${index + 1} must be an object.`);
    }
    const remediation = candidate.remediation;
    if (
      typeof candidate.id !== "string" ||
      typeof candidate.rule_id !== "string" ||
      typeof candidate.title !== "string" ||
      !severities.includes(candidate.severity as Severity) ||
      typeof candidate.score !== "number" ||
      !Number.isFinite(candidate.score) ||
      typeof candidate.target !== "string" ||
      !isRecord(remediation) ||
      typeof remediation.kind !== "string" ||
      typeof remediation.summary !== "string"
    ) {
      throw new Error(`Finding ${index + 1} is missing required fields.`);
    }
    if (candidate.steps !== undefined && !isStringArray(candidate.steps)) {
      throw new Error(`Finding ${index + 1} has invalid path steps.`);
    }
    if (
      remediation.suggested !== undefined &&
      !isStringArray(remediation.suggested)
    ) {
      throw new Error(`Finding ${index + 1} has invalid remediation steps.`);
    }
    if (candidate.evidence !== undefined && !isRecord(candidate.evidence)) {
      throw new Error(`Finding ${index + 1} has invalid evidence.`);
    }
    return candidate as Finding;
  });
  return {
    schema_version: value.schema_version,
    generated_at:
      typeof value.generated_at === "string" ? value.generated_at : undefined,
    findings,
  };
}

const severityRank: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function readFile(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => resolve(String(reader.result ?? "")));
    reader.addEventListener("error", () =>
      reject(new Error("The selected file could not be read.")),
    );
    reader.readAsText(file);
  });
}

export default function App() {
  const [data, setData] = useState<Findings | null>(null);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<Severity | "all">("all");

  const onFile = async (file: File | null) => {
    if (!file) return;
    try {
      const text = await readFile(file);
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new Error("The selected file is not valid JSON.");
      }
      setData(validateFindings(parsed));
      setError("");
      setSearch("");
      setSeverity("all");
    } catch (cause) {
      setData(null);
      setError(
        cause instanceof Error
          ? cause.message
          : "The selected file is not valid JSON.",
      );
    }
  };

  const visible = useMemo(() => {
    const query = search.trim().toLowerCase();
    return [...(data?.findings ?? [])]
      .filter((finding) => severity === "all" || finding.severity === severity)
      .filter((finding) =>
        query === ""
          ? true
          : [
              finding.id,
              finding.rule_id,
              finding.title,
              finding.target,
              finding.target_name ?? "",
            ]
              .join(" ")
              .toLowerCase()
              .includes(query),
      )
      .sort(
        (left, right) =>
          severityRank[right.severity] - severityRank[left.severity] ||
          right.score - left.score ||
          left.id.localeCompare(right.id),
      );
  }, [data, search, severity]);

  const counts = useMemo(
    () =>
      Object.fromEntries(
        severities.map((level) => [
          level,
          data?.findings.filter((finding) => finding.severity === level)
            .length ?? 0,
        ]),
      ) as Record<Severity, number>,
    [data],
  );

  return (
    <main>
      <header>
        <p className="eyebrow">AWS IAM attack paths</p>
        <h1>Panoptes findings review</h1>
        <p>
          Open a local findings file. The browser does not upload it or contact
          AWS.
        </p>
      </header>

      <section className="import-panel" aria-labelledby="import-title">
        <div>
          <h2 id="import-title">Open findings.json</h2>
          <p>Panoptes schema 1.x files are supported.</p>
        </div>
        <label className="file-button">
          Choose JSON
          <input
            aria-label="Choose findings JSON"
            type="file"
            accept="application/json,.json"
            onChange={(event) => void onFile(event.target.files?.[0] ?? null)}
          />
        </label>
      </section>

      {error ? (
        <p role="alert" className="error">
          {error}
        </p>
      ) : null}

      {data ? (
        <>
          <section className="summary" aria-label="Finding counts">
            <article>
              <span>Total</span>
              <strong>{data.findings.length}</strong>
            </article>
            {severities.map((level) => (
              <article key={level} className={`severity-${level}`}>
                <span>{level}</span>
                <strong>{counts[level]}</strong>
              </article>
            ))}
          </section>

          {data.findings.length === 0 ? (
            <section className="empty">
              <h2>No findings</h2>
              <p>The analyzed graph passed the selected rules.</p>
            </section>
          ) : (
            <>
              <section className="controls" aria-label="Finding filters">
                <label>
                  Search
                  <input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="ID, rule, role, or title"
                  />
                </label>
                <label>
                  Severity
                  <select
                    value={severity}
                    onChange={(event) =>
                      setSeverity(event.target.value as Severity | "all")
                    }
                  >
                    <option value="all">All severities</option>
                    {severities.map((level) => (
                      <option key={level} value={level}>
                        {level}
                      </option>
                    ))}
                  </select>
                </label>
              </section>

              {visible.length === 0 ? (
                <p className="empty">No findings match these filters.</p>
              ) : null}
              <ol className="findings">
                {visible.map((finding) => (
                  <li key={finding.id} className="finding-card">
                    <div className="finding-heading">
                      <div>
                        <span className={`badge severity-${finding.severity}`}>
                          {finding.severity}
                        </span>
                        <span className="finding-id">{finding.id}</span>
                      </div>
                      <strong>{Math.round(finding.score * 100)} risk</strong>
                    </div>
                    <h2>{finding.title}</h2>
                    <p className="target">
                      {finding.target_name ?? finding.target}
                    </p>
                    <p>{finding.remediation.summary}</p>
                    <details>
                      <summary>Path, evidence, and remediation</summary>
                      {finding.steps?.length ? (
                        <ol>
                          {finding.steps.map((step, index) => (
                            <li key={`${finding.id}-path-${index}`}>{step}</li>
                          ))}
                        </ol>
                      ) : (
                        <p>No explicit path was recorded.</p>
                      )}
                      {finding.remediation.suggested?.length ? (
                        <>
                          <h3>Suggested review</h3>
                          <ul>
                            {finding.remediation.suggested.map(
                              (step, index) => (
                                <li key={`${finding.id}-fix-${index}`}>
                                  {step}
                                </li>
                              ),
                            )}
                          </ul>
                        </>
                      ) : null}
                      {finding.evidence ? (
                        <>
                          <h3>Evidence</h3>
                          <pre>{JSON.stringify(finding.evidence, null, 2)}</pre>
                        </>
                      ) : null}
                    </details>
                  </li>
                ))}
              </ol>
            </>
          )}
        </>
      ) : null}
    </main>
  );
}
