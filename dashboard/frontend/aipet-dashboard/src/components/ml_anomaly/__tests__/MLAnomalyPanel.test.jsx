import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import MLAnomalyPanel from "../MLAnomalyPanel";
import * as api from "../api/mlAnomalyApi";

jest.mock("../api/mlAnomalyApi");

const ACTIVE_MODEL = {
  id: 1, version_tag: "v20260424_201837", algorithm: "isolation_forest",
  is_active: true, f1_score: 0.98, precision_score: 0.97, recall_score: 0.99,
  training_samples: 5250, created_at: new Date().toISOString(), node_meta: {},
};

beforeEach(() => {
  api.listModels.mockResolvedValue([ACTIVE_MODEL]);
  api.listDetections.mockResolvedValue({ detections: [] });
});

test("renders loading state initially", () => {
  api.listModels.mockImplementation(() => new Promise(() => {}));
  api.listDetections.mockImplementation(() => new Promise(() => {}));
  render(<MLAnomalyPanel token="tok" />);
  expect(screen.getByText(/Loading ML Anomaly/)).toBeInTheDocument();
});

test("renders active model version after fetch", async () => {
  render(<MLAnomalyPanel token="tok" />);
  // version_tag appears in both ModelStatusBar and ModelVersionsTable; use getAllByText
  await waitFor(() => {
    const els = screen.getAllByText("v20260424_201837");
    expect(els.length).toBeGreaterThan(0);
  });
});

test("renders empty detections state", async () => {
  render(<MLAnomalyPanel token="tok" />);
  await waitFor(() => expect(screen.getByText(/No detections yet/)).toBeInTheDocument());
});

test("renders error state when API fails", async () => {
  api.listModels.mockRejectedValue(new Error("[500] server error"));
  api.listDetections.mockRejectedValue(new Error("[500] server error"));
  render(<MLAnomalyPanel token="tok" />);
  await waitFor(() => expect(screen.getByText(/Error loading ML Anomaly/)).toBeInTheDocument());
});

test("renders model version in ModelVersionsTable section", async () => {
  render(<MLAnomalyPanel token="tok" />);
  await waitFor(() => expect(screen.getByText("ACTIVE")).toBeInTheDocument());
});
