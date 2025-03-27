# Scenario: Brute Force Detection

## Scenario Description:
	
During routine log analysis, an abnormal pattern of failed login attempts was detected on multiple endpoints within the organization’s infrastructure. The attempts originated from various external IP addresses, suggesting a distributed brute-force attack targeting Active Directory accounts. Further analysis revealed that some of the source IPs are associated with known malicious actors. Given the high volume and frequency of failed attempts, there is a strong indication of credential-stuffing or password-guessing techniques being used.
---

## Log Source:

● Windows Security Logs (EventCode 4625) from Domain Controllers

● Firewall logs capturing inbound authentication attempts

● IDS/IPS alerts for repeated failed login attempts

● VPN authentication logs (if applicable) to track remote access attempts

● Threat intelligence feeds to correlate source IPs with known attack indicators


	

---

## Detection Query (Splunk):
```

index=windows EventCode=4625  
| stats count by src_ip, user  
| where count > 10  
| sort - count  

```

---

## Attack Simulation:

1. Set Up a Test Environment

	● Use a Windows domain controller or an authentication server.

	● Enable logging for failed login attempts (Event ID 4625).

2. Perform a Brute Force Simulation

	● Use Hydra, Medusa, or ncrack to attempt multiple failed logins:

         --hydra -l testuser -P passwords.txt <target-IP> rdp

	● Alternatively, manually enter incorrect passwords multiple times on a test account.

3. Verify Detection in Splunk

	● Run the detection query in Splunk to confirm logs are captured.

	● Identify patterns such as repeated attempts from the same IP.

4. Analyze Log Data

	● Look for triggered alerts.

	● Investigate the source IP and associated accounts.



---

## Investigation Steps:

1. Verify logs in Splunk.
2. Check IP or hash reputation (VirusTotal, AbuseIPDB).
3. Review system activity and user actions.
4. Confirm suspicious behavior.

---

## Mitigation:

● To counter this brute-force attack and reinforce security within my SOC workflow:

● Immediately block malicious IPs at the firewall and update IDS/IPS rules.

● Adjust Active Directory account lockout settings to restrict repeated failed attempts.

● Implement MFA on all privileged accounts to reduce unauthorized access risks.

● Correlate login attempts across endpoints using Splunk to detect attack spread.

● Set up a custom Splunk alert for high failed login rates, fine-tuned to my environment.

● Perform user awareness training to prevent credential stuffing from leaked passwords.





---

## Conclusion:

Through detailed log analysis and Splunk correlation, I identified a targeted brute-force attack in my simulated SOC setup. The attack was mitigated by blocking attacker IPs, refining security policies, and enhancing detection with Splunk alerts. Moving forward, I'll reinforce my security stack by testing additional SIEM detection rules, tuning threat intelligence feeds, and continuously monitoring authentication logs to stay ahead of evolving brute-force tactics.
