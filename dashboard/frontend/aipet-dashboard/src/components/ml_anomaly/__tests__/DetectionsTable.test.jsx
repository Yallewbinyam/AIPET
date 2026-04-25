import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import "@testing-library/jest-dom";
import DetectionsTable from "../DetectionsTable";

const makeDetections = (n) =>
  Array.from({ length: n }, (_, i) => ({
    id: i + 1, target_ip: `10.0.0.${i + 1}`,
    severity: i % 3 === 0 ? "high" : i % 3 === 1 ? "medium" : "low",
    anomaly_score: 0.4 + i * 0.01,
    is_anomaly: i % 2 === 0,
    detected_at: new Date().toISOString(),
  }));

test("renders empty state when no detections", () => {
  render(<DetectionsTable detections={[]} onRowClick={() => {}} />);
  expect(screen.getByText(/No detections yet/)).toBeInTheDocument();
});

test("renders rows for detections", () => {
  render(<DetectionsTable detections={makeDetections(3)} onRowClick={() => {}} />);
  expect(screen.getByText("10.0.0.1")).toBeInTheDocument();
  expect(screen.getByText("10.0.0.3")).toBeInTheDocument();
});

test("shows max 20 rows per page", () => {
  render(<DetectionsTable detections={makeDetections(25)} onRowClick={() => {}} />);
  const rows = screen.getAllByRole("row");
  // 20 data rows + 1 header = 21
  expect(rows.length).toBe(21);
  expect(screen.getByText(/Load more/)).toBeInTheDocument();
});

test("load more button reveals more rows", () => {
  render(<DetectionsTable detections={makeDetections(25)} onRowClick={() => {}} />);
  fireEvent.click(screen.getByText(/Load more/));
  const rows = screen.getAllByRole("row");
  expect(rows.length).toBe(26); // 25 + header
});

test("calls onRowClick with detection id when row clicked", () => {
  const onRowClick = jest.fn();
  render(<DetectionsTable detections={makeDetections(3)} onRowClick={onRowClick} />);
  fireEvent.click(screen.getByText("10.0.0.2"));
  expect(onRowClick).toHaveBeenCalledWith(2);
});
