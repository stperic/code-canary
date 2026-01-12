# CodeCanary Testing Methodology

> **Note:** This document expands on the testing methodology outlined in [PRD.md Section 10](../PRD.md#10-testing-methodology).

## Overview

This guide provides detailed instructions for conducting reproducible CodeCanary benchmarks.

## Prerequisites

- CodeCanary installed (`pip install codecanary`)
- Target AI assistant installed and configured
- Fresh workspace (no cached context)

## Step-by-Step Protocol

### 1. Environment Preparation

```bash
# Create a fresh bait repository
codecanary init --output ./bait_repo

# Record the commit hash for reproducibility
cd bait_repo && git rev-parse HEAD
```

### 2. AI Assistant Setup

1. Open the bait repository in your AI assistant
2. Wait for indexing to complete:
   - **Cursor**: Check the indexing indicator in the status bar
   - **Copilot**: Wait ~30 seconds after opening
   - **Windsurf**: Check the context panel
3. Verify the assistant can see the bait files by asking: "What files are in this project?"

### 3. Guardrail Configuration (Optional)

If testing guardrail efficacy:

```bash
# Copy the appropriate guardrails file
cp ~/.codecanary/guardrails/cursorrules.txt ./bait_repo/.cursorrules

# Record the hash
sha256sum .cursorrules
```

### 4. Test Execution

For each test case in `prompts.yaml`:

1. Copy the exact prompt text
2. Paste into the AI assistant chat
3. Wait for complete response (do not interrupt)
4. Save the full response to `./responses/{test_id}.py`

### 5. Scanning

```bash
codecanary scan --input ./responses --output ./results/findings.json
```

### 6. Reporting

```bash
codecanary report --format summary
codecanary report --format json --output ./results/report.json
```

## Controlled Variables

| Variable | How to Control |
|----------|----------------|
| Repository state | Use git commit hash |
| Workspace state | Close all other projects |
| AI settings | Document model version, temperature if available |
| Prompt text | Use exact text from test case |
| Response capture | Copy full response, not partial |

## Common Issues

### AI doesn't see bait files
- Ensure indexing is complete
- Try closing and reopening the repository
- Check if `.gitignore` is excluding bait files

### Inconsistent results
- Ensure workspace is clean between runs
- Use same prompt delivery method (chat vs inline)
- Document any assistant updates between runs

## See Also

- [PRD.md - Testing Methodology](../PRD.md#10-testing-methodology)
- [PRD.md - Enterprise Decision Framework](../PRD.md#11-enterprise-decision-framework)
