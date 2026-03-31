import React, { useState } from "react";

type Remediation = { kind: string; summary: string; suggested?: string[] };
type Finding = {
  id: string;
  rule_id: string;
  title: string;
  severity: string;
  steps?: string[];
  score: number;
  target: string;
  target_name?: string;
  remediation: Remediation;
};
type Findings = { findings: Finding[] };

export default function App() {
  const [findings, setFindings] = useState<Findings | null>(null);

  const onFile = async (f: File | null) => {
    if (!f) return;
    const text = await f.text();
    try {
      const data = JSON.parse(text) as Findings;
      setFindings(data);
    } catch {
      alert("Invalid findings.json");
    }
  };

  return (
    <div style={{ padding: 16 }}>
      <h1>Panoptes Findings</h1>
      <input
        type="file"
        accept="application/json"
        onChange={(e) => onFile(e.target.files?.[0] || null)}
      />
      {findings && (
        <ol>
          {findings.findings.map((f) => (
            <li key={f.id}>
              <strong>{f.id}</strong> — {f.title} — {f.severity} — score{" "}
              {f.score.toFixed(2)}
              <div>{f.target_name ?? f.target}</div>
              <div>{f.remediation.summary}</div>
              {f.steps?.length ? (
                <ul>
                  {f.steps.map((s, i) => (
                    <li key={i}>{s}</li>
                  ))}
                </ul>
              ) : null}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
