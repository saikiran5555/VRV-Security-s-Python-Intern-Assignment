import re
import csv
from collections import Counter

# Constants
DEFAULT_THRESHOLD = 10
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"

def parse_log_file(file_path):
    """Parse the log file and extract IPs, endpoints, and failed login attempts."""
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = Counter()
    
    failed_status_code = "401"
    failed_message = "Invalid credentials"

    try:
        with open(file_path, "r") as file:
            for line in file:
                # Regex patterns
                ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                endpoint_pattern = r'\"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (\/\S*)'
                
                # Extract IP addresses
                ip_match = re.search(ip_pattern, line)
                if ip_match:
                    ip = ip_match.group(1)
                    ip_requests[ip] += 1

                # Extract endpoints
                endpoint_match = re.search(endpoint_pattern, line)
                if endpoint_match:
                    endpoint = endpoint_match.group(1)
                    endpoint_requests[endpoint] += 1
                
                # Detect failed login attempts
                if failed_status_code in line or failed_message in line:
                    if ip_match:
                        failed_logins[ip] += 1
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return None, None, None

    return ip_requests, endpoint_requests, failed_logins

def display_table(data, headers):
    """Display data in a tabular format."""
    col_widths = [max(len(str(row[i])) for row in data + [headers]) for i in range(len(headers))]
    row_format = "| " + " | ".join(f"{{:<{w}}}" for w in col_widths) + " |"

    border = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"
    print(border)
    print(row_format.format(*headers))
    print(border)
    for row in data:
        print(row_format.format(*row))
    print(border)

def count_requests_per_ip(ip_requests):
    """Display and return IP request counts sorted in descending order."""
    print("\n**Requests per IP**")
    headers = ["IP Address", "Request Count"]
    data = [(ip, count) for ip, count in ip_requests.most_common()]
    display_table(data, headers)
    return data

def most_frequent_endpoint(endpoint_requests):
    """Identify and display the most frequently accessed endpoint."""
    print("\n**Most Frequently Accessed Endpoint**")
    headers = ["Endpoint", "Access Count"]
    most_frequent = endpoint_requests.most_common(1)
    if most_frequent:
        endpoint, count = most_frequent[0]
        display_table([(endpoint, count)], headers)
        return (endpoint, count)
    else:
        print("No endpoints accessed.")
        return "None", 0

def detect_suspicious_activity(failed_logins, threshold):
    """Identify and display suspicious activity based on failed login attempts."""
    print("\n**Suspicious Activity Detected**")
    headers = ["IP Address", "Failed Login Attempts"]
    data = [(ip, count) for ip, count in failed_logins.items() if count > threshold]
    if data:
        display_table(data, headers)
    else:
        print("No suspicious activity detected.")
    return data

def save_to_csv(ip_data, endpoint_data, suspicious_data, output_file):
    """Save the results to a CSV file."""
    with open(output_file, "w", newline="") as file:
        writer = csv.writer(file)
        
        # Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_data)
        writer.writerow([])  # Empty row for separation
        
        # Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(endpoint_data)
        writer.writerow([])  # Empty row for separation
        
        # Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_data)
        
    print(f"\nResults saved to {output_file}")

def main():
    print("==============================")
    print("     LOG ANALYSIS REPORT     ")
    print("==============================\n")
    
    ip_requests, endpoint_requests, failed_logins = parse_log_file(LOG_FILE)
    if not ip_requests:
        return
    
    # Analyze and display results
    ip_data = count_requests_per_ip(ip_requests)
    endpoint_data = most_frequent_endpoint(endpoint_requests)
    suspicious_data = detect_suspicious_activity(failed_logins, DEFAULT_THRESHOLD)
    
    # Save results to CSV
    save_to_csv(ip_data, endpoint_data, suspicious_data, OUTPUT_FILE)

if __name__ == "__main__":
    main()
