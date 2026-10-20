# Feature Specification: Document the Broker Version Command

**Feature Branch**: `speckit/issue-255`

**Created**: 2026-10-20

**Status**: Draft — NEEDS CLARIFICATION

**Input**: User description:

> Smoke test: document the version command
>
> Document how an operator displays the broker version. Include a concrete command and expected output. Do not change runtime behavior.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Identify the Broker Version (Priority: P1)

As an operator, I want instructions showing how to display the broker version, with a concrete command and its expected output, so that I can identify the version I am operating without guessing the invocation or interpreting an unexplained result.

**Why this priority**: This is the sole requested operator flow and the entire documentation deliverable.

**Independent Test**: Starting from the operator documentation and the documented prerequisites, follow the command and compare its result with the documented output. No runtime changes may be needed to make the instructions work. The exact invocation and output remain subject to Q1 below.

**Acceptance Scenarios**:

1. **Given** an operator with access to the broker artifact described in the documentation, **When** they follow the documented version-display instructions, **Then** they can run a concrete command and identify the broker version from its output using the accompanying expected-output example.
2. **Given** an operator whose broker version differs from the documentation's example version, **When** they compare their result with that example, **Then** the documentation makes clear which value varies and does not imply the example version is their installed version.

These scenarios retain the constitution's 1:1 E2E traceability obligation for a later implementation phase. This specification does not grant a testing exception or authorize changes to runtime behavior to satisfy a test.

### Edge Cases

- The installed version differs from the example: label the output as representative and explain which value identifies the actual version.
- The command requires a particular artifact or execution location: state those prerequisites rather than imply universal availability.
- The expected version-display capability is absent: do not document an unsupported command as working or add runtime support within this documentation-only feature. Resolve Q1 first.

## Concrete Example Journeys *(mandatory)*

### Journey 1 — Read and Display the Broker Version (User Story 1, Scenarios 1.1 and 1.2)

**Cast**: Sam, an operator, has the broker artifact covered by the eventual instructions and wants its version for a support report.

**Step 1 — Locate the instructions**

Sam opens the operator documentation and finds a section explaining how to display the broker version, including the required artifact and execution context.

**Step 2 — Run the documented command**

Sam copies the documented concrete command without needing to inspect source code. The actual command is pending Q1; neither `agentic-identity-broker version` nor `agentic-identity-broker --version` is asserted to work by this draft.

**Step 3 — Compare the output**

Sam compares the result with the documented output and identifies the version to include in the support report. If Sam's version differs from the sample, the explanation makes that variation explicit.

**Observable result**: Sam can report the version displayed by the command, rather than copying a sample version from the documentation.

**Example completeness**: The concrete command, exact expected output, and representative version value cannot yet be supplied truthfully. This journey is intentionally incomplete pending Q1, not an invented successful transcript. No HTTP, UI, JWT, or configuration change is part of this flow.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Operator-facing documentation MUST explain how to display the broker version and state the prerequisites needed to follow the instructions.
- **FR-002**: The documentation MUST include a concrete, copyable command that works for the stated broker artifact without runtime modifications. [NEEDS CLARIFICATION: Q1 — Which existing broker artifact and supported command should be documented, and what exact output does it produce? The current broker CLI source has no version subcommand or configured version flag. If no such command exists, what documentation-only way of identifying the version is acceptable?]
- **FR-003**: The documentation MUST include the expected output corresponding to FR-002, label sample values as examples, and explain which value identifies the broker version.
- **FR-004**: Delivery MUST NOT change runtime behavior, including commands, flags, output, startup, or version handling. No new version-display capability is authorized.
- **FR-005**: Scope MUST remain limited to version-display documentation and the validation required for that documentation. No new API, configuration, persistence, frontend behavior, or architectural decision is introduced.

### Clarification Context

Source inspection of `cmd/agentic-identity-broker/root.go` found a root command without a configured version value and an `init()` that registers configuration, logging, server, refresh, and request-context flags, but no version flag or subcommand. `cmd/agentic-identity-broker/main.go` delegates to that root command. This is evidence of an unresolved documentation target, not permission to add a command. No candidate version command was executed and no output was observed.

Q1 must be resolved in the separate clarification phase before the successful command/output example and the related acceptance expectations can be finalized. No stakeholder decision is assumed.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An operator following the documented prerequisites can identify the broker version using the single documented command, without consulting source code or requesting additional instructions.
- **SC-002**: The documentation contains at least one concrete command paired with its expected output, with every version-dependent sample value explicitly identified as illustrative.
- **SC-003**: Review confirms zero runtime behavior changes are required or included to make the documented instructions accurate.

## Assumptions

- The feature is documentation-only; the words “version command” do not authorize implementing a missing command.
- The reader is an operator with access to the artifact and execution context identified by the eventual instructions, not necessarily a source checkout.
- Existing operator documentation is the default home for the instructions; selecting its exact location is a later planning detail.
- Availability of an existing version-display method is unresolved, not assumed. The artifact, invocation, and real output are dependencies on the answer to Q1.
- Tests and documentation implementation belong to later phases. No constitutional testing exception is inferred from the documentation-only scope.
