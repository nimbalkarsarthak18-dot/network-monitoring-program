# Network Security Monitoring System

A small Python defensive-security project for learning and evidence collection.

## Requirements
- Python 3.10 or newer
- No third-party Python packages required



5. For a safe first test, press Enter to use `localhost`, then choose option `1`.
6. The CSV report is saved in the `reports` folder.

## Safety
Use only on your own computer or a host/network you are explicitly authorized to test. The program accepts only localhost or private/loopback IP addresses and checks a limited list of TCP ports. It does not exploit services or collect credentials.

## Understanding the results
- `OPEN`: a TCP connection succeeded at the time of the test. Confirm the service is intended.
- `CLOSED`: the host refused the connection.
- `NO RESPONSE`: the connection timed out; this does not prove the port is closed.
- `ERROR`: another connection error occurred.

## Suggested evidence for a project submission
1. Screenshot of the program starting in VS Code.
2. Screenshot of the port-check results.
3. Screenshot of the generated CSV report opened in Excel or VS Code.
4. A short report explaining scope, methodology, test results, and limitations.

Do not claim results you have not actually observed. This is a basic monitoring demonstration, not a comprehensive vulnerability scanner.
