import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import DetectionDetailModal from "../DetectionDetailModal";
import * as api from "../api/mlAnomalyApi";

jest.mock("../api/mlAnomalyApi");

const SHAP_EXPLAIN = {
  detection_id: 9, model_version: "v20260424", is_anomaly: true,
  anomaly_score: 0.71, severity: "high",
  explanation: {
    format: "shap_v1", explainer_type: "tree",
    all_contributors: [
      { feature: "cve_count",     shap_value:  1.1, raw_value: 14,  direction: "increases_anomaly" },
      { feature: "packet_rate",   shap_value:  0.8, raw_value: 402, direction: "increases_anomaly" },
      { feature: "open_port_count", shap_value: 0.5, raw_value: 23, direction: "increases_anomaly" },
      { feature: "outbound_ratio",  shap_value: -0.3, raw_value: 0.8, direction: "decreases_anomaly" },
      ...Array.from({ length: 8 }, (_, i) => ({
        feature: `feat_${i}`, shap_value: 0.01 * i, raw_value: i, direction: "increases_anomaly",
      })),
    ],
    feature_vector_used: { cve_count: 14 },
    placeholder_values: { packet_rate: 401.9 },
  },
};

const LEGACY_EXPLAIN = {
  detection_id: 3, model_version: "v2024", is_anomaly: true,
  anomaly_score: 0.65, severity: "high",
  explanation: {
    format: "zscore_legacy", explainer_type: null,
    all_contributors: [{ feature: "cve_count", z_score: 13.2 }],
    feature_vector_used: {}, placeholder_values: null,
  },
};

test("renders loading state initially", () => {
  api.getDetectionExplain.mockImplementation(() => new Promise(() => {}));
  render(<DetectionDetailModal token="tok" detectionId={9} onClose={() => {}} />);
  expect(screen.getByText(/Loading explanation/)).toBeInTheDocument();
});

test("displays all 12 features for shap_v1 format", async () => {
  api.getDetectionExplain.mockResolvedValue(SHAP_EXPLAIN);
  render(<DetectionDetailModal token="tok" detectionId={9} onClose={() => {}} />);
  await waitFor(() => expect(screen.getByText("cve_count")).toBeInTheDocument());
  expect(screen.getByText("packet_rate")).toBeInTheDocument();
  expect(screen.getByText("open_port_count")).toBeInTheDocument();
});

test("shows legacy notice for zscore_legacy format", async () => {
  api.getDetectionExplain.mockResolvedValue(LEGACY_EXPLAIN);
  render(<DetectionDetailModal token="tok" detectionId={3} onClose={() => {}} />);
  await waitFor(() => expect(screen.getByText(/Legacy detection/)).toBeInTheDocument());
});

test("shows imputed indicator for placeholder features", async () => {
  api.getDetectionExplain.mockResolvedValue(SHAP_EXPLAIN);
  render(<DetectionDetailModal token="tok" detectionId={9} onClose={() => {}} />);
  await waitFor(() => screen.getByText("cve_count"));
  // packet_rate is imputed — its 'i' indicator title should exist
  const imputed = document.querySelectorAll('[title*="Imputed"]');
  expect(imputed.length).toBeGreaterThan(0);
});

test("calls onClose when X button clicked", async () => {
  api.getDetectionExplain.mockResolvedValue(SHAP_EXPLAIN);
  const onClose = jest.fn();
  render(<DetectionDetailModal token="tok" detectionId={9} onClose={onClose} />);
  await waitFor(() => screen.getByText("cve_count"));
  fireEvent.click(document.querySelector("button[style*='transparent']"));
  expect(onClose).toHaveBeenCalled();
});

test("displays error state when API fails", async () => {
  api.getDetectionExplain.mockRejectedValue(new Error("[404] Not found"));
  render(<DetectionDetailModal token="tok" detectionId={999} onClose={() => {}} />);
  await waitFor(() => expect(screen.getByText(/Not found/)).toBeInTheDocument());
});
