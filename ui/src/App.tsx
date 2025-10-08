import React, { useState } from 'react'

type Finding = { id: string; title: string; steps: string[]; score: number; target: string }
type Findings = { findings: Finding[] }

export default function App() {
  const [findings, setFindings] = useState<Findings | null>(null)

  const onFile = async (f: File | null) => {
    if (!f) return
    const text = await f.text()
    try {
      const data = JSON.parse(text) as Findings
      setFindings(data)
    } catch {
      alert('Invalid findings.json')
    }
  }

  return (
    <div style={{ padding: 16 }}>
      <h1>Panoptes Findings</h1>
      <input type="file" accept="application/json" onChange={(e) => onFile(e.target.files?.[0] || null)} />
      {findings && (
        <ol>
          {findings.findings.map(f => (
            <li key={f.id}>
              <strong>{f.id}</strong> — {f.title} — score {f.score.toFixed(2)}
              <ul>
                {f.steps.map((s, i) => <li key={i}>{s}</li>)}
              </ul>
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}
