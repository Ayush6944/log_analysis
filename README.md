Log Analysis Script
Overview
This Python script analyzes server log files to extract security insights, track access patterns, and identify potential threats. It processes log entries to generate reports on IP-based traffic, endpoint access frequency, and suspicious login attempts.
Features

Count and analyze requests per IP address
Identify most frequently accessed endpoints
Detect suspicious activities (e.g., potential brute force attempts)
Generate both terminal output and CSV reports
Configurable thresholds for suspicious activity detection

Requirements

Python 3.7+
No external dependencies required (uses standard library only)

Installation

Clone this repository or download the script:

bashCopygit clone <l>
# or
download log_analysis.py

Ensure you have Python 3.7 or higher installed:


Terminal output showing:

Requests per IP address
Most frequently accessed endpoint
Suspicious activity report


CSV file (log_analysis_results.csv) containing:

IP address request counts
Most accessed endpoints
Suspicious activity details



Configuration
You can modify the following parameters in the script:

failed_login_threshold: Number of failed attempts before flagging an IP (default: 10)
Output file name and location
Log file path

Example Output
Terminal Output
Copy=== Log Analysis Results ===

Requests per IP Address:
----------------------------------------
IP Address           Request Count   
----------------------------------------
192.168.1.1          7              
198.51.100.23        7              
203.0.113.5          8              
10.0.0.2             6              

Most Frequently Accessed Endpoint:
----------------------------------------
/home (Accessed 5 times)

Suspicious Activity (Failed Login Attempts):
----------------------------------------
IP Address           Failed Attempts  
----------------------------------------
203.0.113.5          8              
192.168.1.100        5
Error Handling
The script includes robust error handling for:

Missing log files
Malformed log entries
File permission issues
CSV writing errors

Customization
You can extend the script by:

Adding new analysis metrics
Modifying the output format
Adjusting security thresholds
Adding custom log formats

Contributing
Contributions are welcome! Please feel free to submit pull requests or create issues for bugs and feature requests.
License
This project is licensed under the MIT License - see the LICENSE file for details.
Author
Ayush Srivastava
