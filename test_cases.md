# Test Cases – Security Advisory Digest

## Project Overview
Security Advisory Digest is an AI-powered security advisory analyzer that aggregates GitHub Security Advisories, NVD, and CISA KEV feeds, matches them against a technology stack, and generates actionable Markdown security digests.

---

## Test Case 1: Fetch GitHub Security Advisories

| Field | Value |
|---------|---------|
| Test Case ID | TC-01 |
| Objective | Verify GitHub Security Advisories are fetched successfully |
| Input | GitHub Advisory Feed |
| Expected Result | Advisory data is retrieved and displayed |
| Status | Pass |

## Test Case 2: Fetch NVD Vulnerabilities

| Field | Value |
|---------|---------|
| Test Case ID | TC-02 |
| Objective | Verify NVD vulnerability data retrieval |
| Input | NVD Feed |
| Expected Result | Vulnerability records are loaded successfully |
| Status | Pass |

## Test Case 3: Fetch CISA KEV Feed

| Field | Value |
|---------|---------|
| Test Case ID | TC-03 |
| Objective | Verify CISA Known Exploited Vulnerabilities retrieval |
| Input | CISA KEV Feed |
| Expected Result | KEV entries are fetched successfully |
| Status | Pass |

## Test Case 4: Technology Stack Matching

| Field | Value |
|---------|---------|
| Test Case ID | TC-04 |
| Objective | Verify advisories are matched against the provided technology stack |
| Input | stack.yaml |
| Expected Result | Relevant vulnerabilities are identified |
| Status | Pass |

## Test Case 5: AI Summary Generation

| Field | Value |
|---------|---------|
| Test Case ID | TC-05 |
| Objective | Verify AI-generated summaries |
| Input | Retrieved advisories |
| Expected Result | Concise and meaningful summary generated |
| Status | Pass |

## Test Case 6: Markdown Digest Generation

| Field | Value |
|---------|---------|
| Test Case ID | TC-06 |
| Objective | Verify digest creation |
| Input | Processed advisory data |
| Expected Result | Markdown security digest generated |
| Status | Pass |

## Test Case 7: Empty Technology Stack

| Field | Value |
|---------|---------|
| Test Case ID | TC-07 |
| Objective | Verify handling of empty stack file |
| Input | Empty stack.yaml |
| Expected Result | Appropriate validation message displayed |
| Status | Pass |

## Test Case 8: Invalid Feed Source

| Field | Value |
|---------|---------|
| Test Case ID | TC-08 |
| Objective | Verify error handling |
| Input | Invalid feed URL |
| Expected Result | Error handled gracefully without crashing |
| Status | Pass |

## Test Case 9: Streamlit Application Launch

| Field | Value |
|---------|---------|
| Test Case ID | TC-09 |
| Objective | Verify application startup |
| Input | streamlit run app.py |
| Expected Result | Web application launches successfully |
| Status | Pass |

## Test Case 10: End-to-End Workflow

| Field | Value |
|---------|---------|
| Test Case ID | TC-10 |
| Objective | Verify complete workflow |
| Input | Valid technology stack and advisory feeds |
| Expected Result | Advisories fetched, analyzed, summarized, and digest generated successfully |
| Status | Pass |
