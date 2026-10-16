# Network Security Monitoring System — Project Report

## 1. Objective
Build a small defensive tool that checks selected TCP ports on localhost or an authorized private lab host and records the observations.

## 2. Tools
- Python
- socket, csv, ipaddress, datetime (Python standard library)
- Visual Studio Code

## 3. Methodology
1. Validate that the target is localhost or a private/loopback IP.
2. Attempt a short TCP connection to each selected port.
3. Record the timestamp, port, service label, status, and a brief explanation.
4. Export observations to a CSV file.
5. Review any open ports and determine whether the associated services are needed.

## 4. Test Results
Fill this section only after running the project.

| Test | Target | Port(s) | Observed result | Evidence |
|---|---|---|---|---|
| 1 | localhost | 80, 443, 8080 | Fill in actual result | Screenshot/CSV |
| 2 | localhost | Custom authorized ports | Fill in actual result | Screenshot/CSV |

## 5. Limitations
- Checks only TCP connection status for a limited port list.
- A timeout is not proof that a port is closed.
- Does not identify software versions or verify vulnerabilities.
- Results depend on firewall settings and whether services are running.
- Not a substitute for a professional security assessment.

## 6. Conclusion
Write a conclusion based on the actual observations from your test run.
