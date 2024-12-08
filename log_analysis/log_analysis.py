import csv
from collections import Counter, defaultdict
from typing import Dict, List, Tuple
import re
from dataclasses import dataclass
from datetime import datetime

@dataclass
class LogAnalysisResults:
    """Class to store log analysis results"""
    ip_requests: Dict[str, int]
    endpoint_counts: Dict[str, int]
    suspicious_ips: Dict[str, int]
    most_accessed_endpoint: Tuple[str, int]

class LogAnalyzer:
    def __init__(self, failed_login_threshold: int = 10):
        """Initialize the log analyzer with configurable threshold"""
        self.failed_login_threshold = failed_login_threshold
        
    def extract_ip_address(self, line: str) -> str:
        """Extract IP address from a log line using regex"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, line)
        return match.group(0) if match else ''

    def extract_endpoint(self, line: str) -> str:
        """Extract endpoint from a log line using regex"""
        endpoint_pattern = r'(?:GET|POST|PUT|DELETE)\s+([^\s]+)'
        match = re.search(endpoint_pattern, line)
        return match.group(1) if match else ''

    def is_failed_login(self, line: str) -> bool:
        """Check if a log line represents a failed login attempt"""
        return ('401' in line or 'Invalid credentials' in line or 
                'Failed login' in line or 'Authentication failed' in line)

    def analyze_log_file(self, log_file_path: str) -> LogAnalysisResults:
        """Analyze the log file and return results"""
        ip_counter = Counter()
        endpoint_counter = Counter()
        failed_login_counter = defaultdict(int)

        try:
            with open(log_file_path, 'r') as file:
                for line in file:
                    # Extract IP address and count requests
                    ip = self.extract_ip_address(line)
                    if ip:
                        ip_counter[ip] += 1

                    # Extract and count endpoints
                    endpoint = self.extract_endpoint(line)
                    if endpoint:
                        endpoint_counter[endpoint] += 1

                    # Check for failed login attempts
                    if self.is_failed_login(line):
                        failed_login_counter[ip] += 1

            # Get most accessed endpoint
            most_accessed = endpoint_counter.most_common(1)[0] if endpoint_counter else ('', 0)

            # Filter suspicious IPs
            suspicious_ips = {
                ip: count for ip, count in failed_login_counter.items()
                if count >= self.failed_login_threshold
            }

            return LogAnalysisResults(
                ip_requests=dict(ip_counter.most_common()),
                endpoint_counts=dict(endpoint_counter),
                suspicious_ips=suspicious_ips,
                most_accessed_endpoint=most_accessed
            )

        except FileNotFoundError:
            print(f"Error: Log file '{log_file_path}' not found.")
            return None
        except Exception as e:
            print(f"Error analyzing log file: {str(e)}")
            return None

    def display_results(self, results: LogAnalysisResults):
        """Display analysis results in the terminal"""
        print("\n=== Log Analysis Results ===\n")
        
        print("Requests per IP Address:")
        print("-" * 40)
        print(f"{'IP Address':<20} {'Request Count':<15}")
        print("-" * 40)
        for ip, count in results.ip_requests.items():
            print(f"{ip:<20} {count:<15}")

        print("\nMost Frequently Accessed Endpoint:")
        print("-" * 40)
        endpoint, count = results.most_accessed_endpoint
        print(f"{endpoint} (Accessed {count} times)")

        print("\nSuspicious Activity (Failed Login Attempts):")
        print("-" * 40)
        print(f"{'IP Address':<20} {'Failed Attempts':<15}")
        print("-" * 40)
        for ip, count in results.suspicious_ips.items():
            print(f"{ip:<20} {count:<15}")

    def save_to_csv(self, results: LogAnalysisResults, output_file: str = 'log_analysis_results.csv'):
        """Save analysis results to CSV file"""
        try:
            with open(output_file, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                
                # Write IP requests section
                writer.writerow(['=== Requests per IP ==='])
                writer.writerow(['IP Address', 'Request Count'])
                for ip, count in results.ip_requests.items():
                    writer.writerow([ip, count])

                # Write most accessed endpoint section
                writer.writerow([])  # Empty row for separation
                writer.writerow(['=== Most Accessed Endpoint ==='])
                writer.writerow(['Endpoint', 'Access Count'])
                endpoint, count = results.most_accessed_endpoint
                writer.writerow([endpoint, count])

                # Write suspicious activity section
                writer.writerow([])  # Empty row for separation
                writer.writerow(['=== Suspicious Activity ==='])
                writer.writerow(['IP Address', 'Failed Login Count'])
                for ip, count in results.suspicious_ips.items():
                    writer.writerow([ip, count])

            print(f"\nResults saved to {output_file}")

        except Exception as e:
            print(f"Error saving results to CSV: {str(e)}")

def main():
    # Initialize analyzer with default threshold
    analyzer = LogAnalyzer(failed_login_threshold=10)
    
    # Analyze log file
    results = analyzer.analyze_log_file('server.log')
    
    if results: 
        # Display results in terminal
        analyzer.display_results(results)
        
        # Save results to CSV
        analyzer.save_to_csv(results)

if __name__ == "__main__":
    main()