# Log File Analysis Script  

## Overview  
This project is a Python-based tool designed to analyze web server log files. It extracts insights like request counts per IP address, the most frequently accessed endpoint, and suspicious activity based on failed login attempts. Results are displayed in a user-friendly terminal output and saved in a structured CSV file for further analysis.

---

## Features  
1. *Request Analysis:* Count the number of requests per IP address.  
2. *Endpoint Insights:* Identify the most frequently accessed endpoint.  
3. *Suspicious Activity Detection:* Flag IP addresses with excessive failed login attempts.  
4. *CSV Report Generation:* Save the analyzed data into a CSV file (log_analysis_results.csv) with the following sections:  
   - *Requests per IP*  
   - *Most Accessed Endpoint*  
   - *Suspicious Activity*  

---

## File Structure  
- log_analysis.py: Main script for parsing and analyzing log files.  
- sample.log: Sample log file for testing.  
- log_analysis_results.csv: Example output file generated after running the script. (output file)

---

## How to Use  
1. Clone the repository:  
   bash
   git clone https://github.com/saikiran5555/VRV-Security-s-Python-Intern-Assignment.git
   cd log-analysis-script
     

2. Ensure Python is installed.  

3. Place your log file in the same directory as the script. By default, the script looks for sample.log.  

4. Run the script:  
   bash
   python log_analysis.py
     

5. View the results in the terminal or open the generated log_analysis_results.csv for detailed analysis.

---

## Example Output  
### Terminal Output:  

==============================
     LOG ANALYSIS REPORT     
==============================


**Requests per IP**
+---------------+---------------+
| IP Address    | Request Count |
+---------------+---------------+
| 203.0.113.5   | 8             |
| 198.51.100.23 | 8             |
| 192.168.1.1   | 7             |
| 10.0.0.2      | 6             |
| 192.168.1.100 | 5             |
+---------------+---------------+

**Most Frequently Accessed Endpoint**
+----------+--------------+
| Endpoint | Access Count |
+----------+--------------+
| /login   | 13           |
+----------+--------------+

**Suspicious Activity Detected**
No suspicious activity detected.

Results saved to log_analysis_results.csv



### CSV Structure:  
- *Requests per IP*: IP Address, Request Count  
- *Most Accessed Endpoint*: Endpoint, Access Count  
- *Suspicious Activity*: IP Address, Failed Login Count  

---

## Why This Project?  
This project demonstrates the ability to work with real-world log data, showcasing skills in:  
- Log file parsing with Python and regular expressions.  
- Data analysis with collections.Counter.  
- Generating structured, actionable reports.  
- Writing modular and reusable code.  

---
