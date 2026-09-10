# IDB30102_GroupN_MobileApplicationSecurity

## Project Title
Automated Static Security Assessment Framework for Android Mobile Applications


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
- Androguard

## How to Run the Project
Install the required libraries:
```python
pip install -r requirements.txt
```
Run the Python files:
```python
python Metadata.py
```
and
```python
python analysis.py
```

## Output
The project generates:

- APK metadata (CSV)
- SHA-256 file hash
- Application and SDK information
- Android component analysis
- Permission analysis
- Vulnerability report (CSV)
- Security findings with severity levels

## Conclusion

The APK Analysis Tool extracts metadata and performs basic static security analysis on Android applications. It identifies security-related information such as permissions, application components, SDK versions, and potential vulnerabilities, including dangerous permissions, debuggable applications, exported components, and backup settings. The generated reports provide a useful foundation for Android malware analysis, vulnerability assessment, and secure mobile application research.


