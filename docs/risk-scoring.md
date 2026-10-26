# Risk scoring methodology

The rules live in `app/scoring.py`, and `tests/test_scoring.py` covers them. The **Scoring and mapping** page in the app reads its numbers from the same constants, so the documentation on screen can't drift from the code.

## Why a simple additive score

The goal is to rank remediation work in a way that anyone can check. A reviewer should be able to look at any finding and recompute its score in their head. Multiplicative or machine-learned scores can rank better in some settings, but they're harder to explain and to challenge. For a dashboard that drives work assignments, being able to explain a score matters more.

## Formula

```
score = min(100, round(
      CVSS base score x 4              # 0 to 40
    + asset criticality x 8            # 8 to 40   (criticality is 1 to 5, set by the organisation)
    + 12 if the asset is internet-facing
    + 15 if the weakness is known to be exploited
    + data classification points       # public 0, internal 2, confidential 5, restricted 8
))
```

| Rating | Score | Remediation target |
|---|---|---|
| Critical | 75 to 100 | 7 days |
| High | 55 to 74 | 30 days |
| Medium | 35 to 54 | 90 days |
| Low | 0 to 34 | 180 days |

- **Due date** = discovery date + the target for the finding's rating. Analysts can override it, and the change is recorded.
- **Overdue** = the finding is open or in progress, and today is after the due date. A finding due today isn't overdue yet.
- Scores are recalculated on every page load. If you change an asset's criticality, exposure or data classification, all of its findings are re-ranked immediately.

## Worked example

A **default administrative credentials** finding (CVSS 9.4) on the **edge firewall pair** (criticality 5, internet-facing, internal data), known to be exploited:

| Factor | Points |
|---|---|
| CVSS 9.4 x 4 | 37.6 |
| Criticality 5 x 8 | 40 |
| Internet-facing | 12 |
| Known exploited | 15 |
| Internal data | 2 |
| **Total** | 106.6, capped at **100**, so the rating is **critical** with a 7-day target |

The same CVSS 9.4 weakness on a criticality-2 staging server that isn't internet-facing scores 37.6 + 16 + 2 = 56: **high**, with a 30-day target. That gap is the point of the score. The same technical flaw matters more on assets the business depends on and that attackers can reach.

## Design decisions and their trade-offs

| Decision | Reason | Trade-off |
|---|---|---|
| Use the CVSS **base** score only | It's widely available and comparable | It ignores exploit maturity (partly covered by the known-exploited bonus) and environmental factors |
| Asset criticality weighs as much as CVSS (40 points each) | The business impact of an asset is as important as the technical severity | A low-severity issue on a critical asset can outrank a severe issue on a minor one, which is intended but debatable |
| Flat bonuses for exposure and known exploitation | Easy to explain | They don't scale with severity |
| Cap at 100 | Keeps the scale readable | Several findings can tie at 100. Ties are broken by finding ID |

## What the score is not

- It isn't a probability of compromise or an estimate of financial loss.
- It isn't a substitute for a risk assessment (RA-3) or for human judgement about compensating controls.
- It hasn't been validated against real incident data. The demo data is synthetic.

## Control verification

Control status is tracked in two separate fields, so that what the organisation claims is never confused with what an assessment has shown:

- **Implementation** is the organisation's claim: implemented, partially implemented, planned, not implemented or not applicable.
- **Assessment result** is what an assessor found: not assessed, satisfied, or other than satisfied (the wording follows SP 800-53A).

The two combine into one **verification state**:

| State | Rule |
|---|---|
| Verified | Satisfied, and assessed within the last 365 days |
| Implemented, not verified | Implemented or partial, with no assessment |
| Assessment expired | Satisfied, but assessed more than 365 days ago |
| Deficient | Other than satisfied, whatever the implementation claim |
| Not implemented | Planned or not implemented |
| Not applicable | Marked not applicable |

A **verified** control is also flagged as *contradicted by findings* when open high or critical findings reference it. A satisfied assessment from months ago doesn't outweigh current evidence that the control isn't working.
