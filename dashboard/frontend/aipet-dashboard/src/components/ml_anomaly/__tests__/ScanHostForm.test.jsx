import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import ScanHostForm from "../ScanHostForm";
import * as api from "../api/mlAnomalyApi";

jest.mock("../api/mlAnomalyApi");

const RESULT = {
  detection_id: 42, target_ip: "10.0.3.11", is_anomaly: true,
  severity: "high", anomaly_score: 0.71, explainer_type: "tree",
  top_contributors: [{ feature: "cve_count", shap_value: 1.1, raw_value: 14, direction: "increases_anomaly" }],
  synthetic_fields: [],
};

test("rejects malformed IP client-side before calling API", () => {
  render(<ScanHostForm token="tok" />);
  fireEvent.change(screen.getByPlaceholderText(/Enter host IP/), { target: { value: "not-an-ip" } });
  fireEvent.click(screen.getByText("Analyse Host"));
  expect(screen.getByText(/Invalid IP format/)).toBeInTheDocument();
  expect(api.predictReal).not.toHaveBeenCalled();
});

test("calls predictReal with correct IP on valid submit", async () => {
  api.predictReal.mockResolvedValue(RESULT);
  render(<ScanHostForm token="tok" />);
  fireEvent.change(screen.getByPlaceholderText(/Enter host IP/), { target: { value: "10.0.3.11" } });
  fireEvent.click(screen.getByText("Analyse Host"));
  await waitFor(() => expect(api.predictReal).toHaveBeenCalledWith("tok", { host_ip: "10.0.3.11" }));
});

test("displays result after successful scan", async () => {
  api.predictReal.mockResolvedValue(RESULT);
  render(<ScanHostForm token="tok" />);
  fireEvent.change(screen.getByPlaceholderText(/Enter host IP/), { target: { value: "10.0.3.11" } });
  fireEvent.click(screen.getByText("Analyse Host"));
  await waitFor(() => expect(screen.getByText("HIGH")).toBeInTheDocument());
});

test("displays error message when API call fails", async () => {
  api.predictReal.mockRejectedValue(new Error("[404] no scan data for this host"));
  render(<ScanHostForm token="tok" />);
  fireEvent.change(screen.getByPlaceholderText(/Enter host IP/), { target: { value: "10.0.0.5" } });
  fireEvent.click(screen.getByText("Analyse Host"));
  await waitFor(() => expect(screen.getByText(/no scan data/)).toBeInTheDocument());
});

test("shows loading state during scan", async () => {
  api.predictReal.mockImplementation(() => new Promise(r => setTimeout(() => r(RESULT), 100)));
  render(<ScanHostForm token="tok" />);
  fireEvent.change(screen.getByPlaceholderText(/Enter host IP/), { target: { value: "10.0.3.11" } });
  fireEvent.click(screen.getByText("Analyse Host"));
  expect(screen.getByText("Analysing…")).toBeInTheDocument();
  await waitFor(() => expect(screen.queryByText("Analysing…")).not.toBeInTheDocument());
});
