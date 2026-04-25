import React from "react";
import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom";
import SHAPBreakdown from "../SHAPBreakdown";

const makeContribs = (overrides = []) => [
  { feature: "cve_count",    shap_value:  1.1, raw_value: 14,  direction: "increases_anomaly" },
  { feature: "packet_rate",  shap_value:  0.8, raw_value: 400, direction: "increases_anomaly" },
  { feature: "outbound_ratio", shap_value: -0.3, raw_value: 0.8, direction: "decreases_anomaly" },
  { feature: "protocol_entropy", shap_value: -0.1, raw_value: 1.2, direction: "decreases_anomaly" },
  ...overrides,
];

test("renders feature names", () => {
  render(<SHAPBreakdown contributors={makeContribs()} />);
  expect(screen.getByText("cve_count")).toBeInTheDocument();
  expect(screen.getByText("packet_rate")).toBeInTheDocument();
});

test("positive shap values show + prefix", () => {
  render(<SHAPBreakdown contributors={makeContribs()} />);
  expect(screen.getByText("+1.1000")).toBeInTheDocument();
});

test("renders imputed indicator when feature in placeholderValues", () => {
  const placeholders = { packet_rate: 401.9 };
  render(<SHAPBreakdown contributors={makeContribs()} placeholderValues={placeholders} />);
  // The 'i' indicator appears for imputed features
  const indicators = document.querySelectorAll('[title*="Imputed"]');
  expect(indicators.length).toBeGreaterThan(0);
});

test("does not render imputed indicator for real features", () => {
  const placeholders = { packet_rate: 401.9 }; // cve_count is NOT imputed
  render(<SHAPBreakdown contributors={makeContribs()} placeholderValues={placeholders} />);
  const indicators = document.querySelectorAll('[title*="Imputed"]');
  // Only 1 imputed feature (packet_rate), not all 4
  expect(indicators.length).toBe(1);
});

test("renders nothing when contributors is empty", () => {
  const { container } = render(<SHAPBreakdown contributors={[]} />);
  expect(container.firstChild).toBeNull();
});

test("compact mode shows only 5 rows", () => {
  const contribs = Array.from({ length: 12 }, (_, i) => ({
    feature: `feat_${i}`, shap_value: 0.1 * i, raw_value: i, direction: "increases_anomaly",
  }));
  render(<SHAPBreakdown contributors={contribs} compact />);
  // Only 5 features rendered
  expect(screen.queryByText("feat_5")).not.toBeInTheDocument();
  expect(screen.getByText("feat_4")).toBeInTheDocument();
});
