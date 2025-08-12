# FUTURE_CS_02
Security Alert Monitoring &amp; Incident Response
 Project Overview
The objective is to simulate the work of a Security Operations Center (SOC) analyst by monitoring, analyzing, and responding to simulated security alerts using Splunk. The focus is on identifying suspicious activity, classifying alerts, and producing an actionable incident response report.


"Setup Instructions"

1.Prepare the Data:

2.Used the file SOC_Task2_Sample_Logs.txt as the data source.

3.Saved the file locally 


""Import into Splunk""

In the Splunk web interface, navigate to Add Data → Upload Files.

Select SOC_Task2_Sample_Logs.txt.

Assigned a source type which is soc_task2_security_logs.

Ensure proper timestamp recognition and event separation.


""Field Extraction""

Configured Splunk to extract:

1.timestamp

2.user

3.ip

4.action

5.threat 


""METHODOLOGY""

1.log injection: The logs were uploaded into Splunk from the provided .txt file and verified for correct timestamp parsing.

2. Parsing & Field Extraction: Splunk’s field extractor was used to create regex patterns to capture user, IP address, action, and threat type.

3. spl queries: sample queries used in this analysis are:

3A..Count failed logins per user/IP

spl usded:
sourcetype="soc_task2_security_logs" action="login failed"| stats count AS failed_attempts BY ip, user| sort - failed_attempts

3B..List malware detections

spl used :sourcetype="soc_task2_security_logs" action="malware detected"| stats count BY user, ip, threat

3C..Suspicious file access attempts

spl usded: sourcetype="soc_task2_security_logs" action="file accessed"| stats count BY user, ip

4. Event Classification:

Incidents were categorized based on severity:

High Severity which are Malware detections (Trojan, Ransomware and Rootkit)

Medium Severity which are Multiple failed logins followed by success (possible brute-force)

Low Severity which are file accesses from known IPs


""Documentation""

All high  and medium-severity events were documented in the final investigation report with time, user, IP, and description of the activity.



""Key Findings""

From the analysis of SOC_Task2_Sample_Logs.txt:

Multiple Malware Detections:

Trojan Detected on multiple accounts (bob, david, eve, charlie) from different IPs.

Ransomware Behavior detected on bob’s account from 172.16.0.3.

Rootkit Signature on alice from 198.51.100.42 and eve from 10.0.0.5.

Spyware Alert and Worm Infection Attempt present in the logs.

Possible Credential Compromise:

Several users had failed logins followed shortly by a successful login from the same IP, indicating possible brute-force or password guessing.

Unusual File Access Patterns:

Sensitive files accessed from external IP ranges (203.0.113.x, 198.51.100.x) that are not part of internal subnets.

Frequent Connection Attempts:

charlie and david showed high volumes of connection attempts to multiple subnets without corresponding legitimate activity.



""Conclusion""

This investigation revealed clear signs of active threats and compromised accounts. Immediate remediation steps include:

Blocking malicious IP addresses

Forcing password resets for affected accounts

Running endpoint malware scans

Reviewing firewall rules for unusual outbound traffic
