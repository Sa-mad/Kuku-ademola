# Scenario: Brute Force Detection

## **Scenario Description:**
	
This documentation explains how to detect brute-force login attempts using Splunk. The focus is on identifying multiple failed login attempts (HTTP 401/403 responses) from the same IP address and user account within a short period.
---

## **Step 1: Data Collection**

Ensure Splunk is ingesting logs that contain authentication events. In this case, we are analyzing web server logs that capture login attempts. The key fields in our logs are:

	● IP Address (source of login attempts)

	● Username (account being used)

	● HTTP Status Code (401 = Unauthorized, 403 = Forbidden)


## **Step 2: Initial Search Query**

We started by writing a basic Splunk Search Processing Language (SPL) query to find failed login attempts.

Query 1: Identify Failed Logins

	● index=* sourcetype=* status=401 OR status=403

This query searches all indexes and source types for events where the status code is 401 (Unauthorized) or 403 (Forbidden), which usually indicate failed logins.


Result:
	● The search returned 201 events, confirming that failed logins were occurring.


## **Step 3: Extracting Relevant Fields**

Since some logs do not explicitly store the IP address as a field, we used regular expressions (regex) to extract it manually from the raw log data.

Query 2: Extract IP and Usernames

	● index=* sourcetype=* status=401 OR status=403 
	| rex field=_raw "(?P<src_ip>\d+\.\d+\.\d+\.\d+)" 
	| stats count by src_ip, user 
	| where count > 10 
	| sort -count

 Explanation:

	● rex field=_raw "(?P<src_ip>\d+\.\d+\.\d+\.\d+)" → Extracts IP addresses from logs.

	● stats count by src_ip, user → Counts occurrences of failed logins by IP address and user.

	● where count > 10 → Filters only IPs with more than 10 failed attempts.

	● sort -count → Sorts results in descending order of login attempts.

Result:

The query successfully identified IP addresses making multiple failed login attempts.


##  **Step 4: Analysis & Findings**
From our analysis, we observed:

	● IP 192.168.1.13 attempted logins multiple times using different usernames:

		● testuser

		● webadmin

This behavior is consistent with brute force attacks, where attackers try multiple username/password combinations.


##  **Step 5: Mitigation & Response**

To prevent further attacks, we recommend:

Blocking the source IP (192.168.1.13) at the firewall level.

Enforcing account lockouts after multiple failed login attempts.

Implementing multi-factor authentication (MFA) to make brute-force attacks harder.

Monitoring logs continuously for similar patterns in the future.




	



