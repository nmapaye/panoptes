import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { describe, expect, it } from "vitest";

import App from "./App";

const findings = {
  schema_version: "1.1.0",
  generated_at: "2026-08-23T00:00:00Z",
  findings: [
    {
      id: "F-LOW",
      rule_id: "AWS-LOW-001",
      title: "Reader trust",
      severity: "low",
      score: 0.4,
      target: "r:reader",
      target_name: "ReaderRole",
      remediation: { kind: "review", summary: "Review the reader trust." },
    },
    {
      id: "F-HIGH",
      rule_id: "AWS-HIGH-001",
      title: "Admin trust",
      severity: "high",
      score: 0.95,
      target: "r:admin",
      target_name: "AdminRole",
      steps: ["ci-bot -> CanAssume -> AdminRole"],
      evidence: { account_id: "111111111111" },
      remediation: {
        kind: "restrict",
        summary: "Restrict the admin trust.",
        suggested: ["Require MFA."],
      },
    },
  ],
};

async function upload(value: unknown, name = "findings.json") {
  const input = screen.getByLabelText("Choose findings JSON");
  const file = new File(
    [typeof value === "string" ? value : JSON.stringify(value)],
    name,
    { type: "application/json" },
  );
  fireEvent.change(input, { target: { files: [file] } });
}

describe("Panoptes findings review", () => {
  it("reports malformed and unsupported files inline", async () => {
    render(<App />);
    await upload("{");
    expect(await screen.findByRole("alert")).toHaveTextContent("JSON");
    await upload({ schema_version: "2.0.0", findings: [] });
    expect(await screen.findByRole("alert")).toHaveTextContent("Unsupported");
  });

  it("summarizes, sorts, searches, filters, and displays details", async () => {
    render(<App />);
    await upload(findings);
    expect(await screen.findByText("Admin trust")).toBeInTheDocument();
    const cards = screen
      .getAllByRole("listitem")
      .filter((item) => item.classList.contains("finding-card"));
    expect(within(cards[0]).getByText("Admin trust")).toBeInTheDocument();
    expect(screen.getByLabelText("Finding counts")).toHaveTextContent("Total2");

    fireEvent.change(screen.getByLabelText("Search"), {
      target: { value: "ReaderRole" },
    });
    expect(screen.queryByText("Admin trust")).not.toBeInTheDocument();
    expect(screen.getByText("Reader trust")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Search"), {
      target: { value: "" },
    });
    fireEvent.change(screen.getByLabelText("Severity"), {
      target: { value: "high" },
    });
    expect(screen.getByText("Admin trust")).toBeInTheDocument();
    expect(screen.queryByText("Reader trust")).not.toBeInTheDocument();
    fireEvent.click(screen.getByText("Path, evidence, and remediation"));
    expect(screen.getByText("Require MFA.")).toBeInTheDocument();
    expect(screen.getByText(/account_id/)).toBeInTheDocument();
  });

  it("shows a clean empty result", async () => {
    render(<App />);
    await upload({ schema_version: "1.1.0", findings: [] });
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: "No findings" }),
      ).toBeInTheDocument(),
    );
  });
});
