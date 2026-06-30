# Report Format

Use these tables exactly for the first review report and the post-fix completion report. Keep language professional enough for client-facing use.

## Security Review Report

```markdown
# Security Review Report

## Project Summary

| Item | Value |
| --- | --- |
| Project type |  |
| Package manager |  |
| Frameworks detected |  |
| Frontend/backend detected |  |
| Overall risk level |  |
| Files reviewed |  |
| Commands used |  |

## Issues Found

| ID | Severity | Category | File/Location | Issue | Impact | Recommended Fix | Breaking Risk |
| --- | --- | --- | --- | --- | --- | --- | --- |

## Package Update Review

| Package | Current | Wanted | Latest | Severity/Risk | Update Type | Suggested Action |
| --- | ---: | ---: | ---: | --- | --- | --- |

## Safe Fixes Available

| Fix ID | Description | Files affected | Risk | Test needed |
| --- | --- | --- | --- | --- |

## Fixes Requiring Approval

| Fix ID | Description | Reason approval is needed | Risk |
| --- | --- | --- | --- |

## Recommended Fix Plan

1. **Step title**
   - What will change:
   - Why it is needed:
   - Files affected:
   - How to test:
   - Rollback idea:
   - Risk level:
```

Severity values: `Critical`, `High`, `Medium`, `Low`, `Info`.

Breaking Risk values: `Safe`, `Low`, `Medium`, `High`, `Requires approval`.

Update Type values: `Patch`, `Minor`, `Major`, `Security fix`, `Hold/manual review`.

## Required Approval Prompt

After the report and plan, ask both questions and wait:

```markdown
Do you want me to start fixing these issues?

Which approach do you prefer?

1. Inline approach - one agent fixes issues one by one in a safe sequence.
2. Subagent approach - specialized subagents review or fix dependencies, frontend security, backend security, secrets/config, and tests.
```

## Security Fix Completion Report

```markdown
# Security Fix Completion Report

## Fix Summary

| Fix ID | Status | Files Changed | Notes |
| --- | --- | --- | --- |

## Tests/Checks Run

| Command | Result | Notes |
| --- | --- | --- |

## Remaining Issues

| ID | Severity | Reason Not Fixed | Next Step |
| --- | --- | --- | --- |

## What Changed

Explain the changes in simple language.

## What User Should Verify

- Login works.
- Protected routes work.
- API calls work.
- Build passes.
- Frontend pages still load.
- Backend starts.
- Environment variables are correct.

## Recommended Next Step

Suggest the next security improvement, but do not continue without approval.
```
