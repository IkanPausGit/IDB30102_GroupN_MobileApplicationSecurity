# IDB30102_GroupN_MobileApplicationSecurity

## Project Title


## Research Problem
Individual static analysis tools used to evaluate Android applications generate inconsistent and incomplete vulnerability coverage, and there is no readily available framework that aggregates multiple tools' findings into a common vulnerability taxonomy (OWASP Mobile Top 10 / CWE) with a consistent severity score (CVSS).

## Research Objective
- To investigate the current static analysis methodologies and vulnerability classification approaches used in Android application security evaluation.
- To provide a prototype system for aggregating and categorizing static-analysis vulnerability discoveries using the OWASP Mobile Top 10 and CWE taxonomy.
- To evaluate the prototype, use vulnerability type coverage and CVSS severity-scoring consistency as evaluation criteria.

## Research Question
Does aggregating results from multiple static analysis tools improve vulnerability-type coverage and severity-scoring consistency compared to a single-tool baseline?

## Methodology
This project employs a security assessment strategy combined with a prototype development model. Sample Android APKs are scanned using various static analysis tools, and the resulting discoveries are classed against the OWASP Mobile Top 10 / CWE taxonomy and scored using CVSS, before being compared to a single-tool baseline.

## Dataset Description
The dataset contains:
- Candidate test APKs
- Standardised vulnerable benchmarks
- Recorded fields per scan

## Tools Used
- Python
- MobSF
- APKTool
- Androguard

## How to Run the Project

## Output

## Conclusion



