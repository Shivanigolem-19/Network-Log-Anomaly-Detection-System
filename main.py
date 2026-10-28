
from datetime import datetime
from collections import Counter
import socket

# 1. Load registered users
users = {}

try:
    with open("users.txt", "r") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            parts = line.split(",")

            if len(parts) == 2:
                username = parts[0].strip()
                password = parts[1].strip()

                if username and password:
                    users[username] = password

except FileNotFoundError:
    print("Error: users.txt was not found.")
    raise SystemExit

if not users:
    print("No registered users found.")
    raise SystemExit


# 2. Display project heading
print("=" * 45)
print("NETWORK LOGIN ANOMALY DETECTION SYSTEM")
print("=" * 45)


# 3. Ask for login credentials
username = input("Enter username: ").strip()
password = input("Enter password: ")

if username in users and users[username] == password:
    event_type = "LOGIN_SUCCESS"
    print("Login successful!")
else:
    event_type = "LOGIN_FAILED"
    print("Login failed! Invalid username or password.")


# 4. Get the current timestamp
timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# 5. Automatically detect the computer's local IP address
try:
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)

except OSError:
    ip_address = "UNKNOWN"

print("Detected local IP address:", ip_address)


# 6. Record the login event
log_record = (
    f"{timestamp},{ip_address},{event_type},{username}\n"
)

with open("sample_logs.txt", "a") as file:
    file.write(log_record)

print("Login attempt recorded in sample_logs.txt")


# 7. Read the login logs
logs = []

try:
    with open("sample_logs.txt", "r") as file:
        for line in file:
            parts = line.strip().split(",")

            if len(parts) != 4:
                continue

            log = {
                "Timestamp": parts[0],
                "IP Address": parts[1],
                "Event Type": parts[2],
                "Username": parts[3]
            }

            logs.append(log)

except FileNotFoundError:
    print("Log file not found.")
    raise SystemExit


# 8. Count failed login attempts by IP and username
failed_ip_count = Counter()
failed_user_count = Counter()

for log in logs:
    if log["Event Type"] == "LOGIN_FAILED":
        failed_ip_count[log["IP Address"]] += 1
        failed_user_count[log["Username"]] += 1


# 9. Detect suspicious login activity
print("\n" + "=" * 45)
print("SUSPICIOUS LOGIN ACTIVITY")
print("=" * 45)

threshold = 3
suspicious_found = False

for ip, count in failed_ip_count.items():
    if count >= threshold:
        suspicious_found = True
        print("Alert: Repeated failed logins detected")
        print("IP Address:", ip)
        print("Failed attempts:", count)
        print("-" * 45)

for user, count in failed_user_count.items():
    if count >= threshold:
        suspicious_found = True
        print("Alert: Suspicious account activity")
        print("Username:", user)
        print("Failed attempts:", count)
        print("-" * 45)

if not suspicious_found:
    print("No repeated failed-login pattern detected.")


# 10. Generate a summary report
total_records = len(logs)

success_count = sum(
    1 for log in logs
    if log["Event Type"] == "LOGIN_SUCCESS"
)

failed_count = sum(
    1 for log in logs
    if log["Event Type"] == "LOGIN_FAILED"
)

different_ips = len(set(
    log["IP Address"] for log in logs
))

different_users = len(set(
    log["Username"] for log in logs
))

print("\n" + "=" * 45)
print("LOGIN SUMMARY REPORT")
print("=" * 45)
print("Total log records:", total_records)
print("Successful logins:", success_count)
print("Failed logins:", failed_count)
print("Different IP addresses:", different_ips)
print("Different usernames:", different_users)


# 11. Save the summary report
with open("security_report.txt", "w") as file:
    file.write("LOGIN SUMMARY REPORT\n")
    file.write("=" * 45 + "\n")
    file.write(f"Total log records: {total_records}\n")
    file.write(f"Successful logins: {success_count}\n")
    file.write(f"Failed logins: {failed_count}\n")
    file.write(f"Different IP addresses: {different_ips}\n")
    file.write(f"Different usernames: {different_users}\n")


# 12. Save failed login details
with open("suspicious_activity.txt", "w") as file:
    file.write("FAILED LOGIN DETAILS\n")
    file.write("=" * 45 + "\n")

    for log in logs:
        if log["Event Type"] == "LOGIN_FAILED":
            file.write(
                f"{log['Timestamp']},"
                f"{log['IP Address']},"
                f"{log['Username']}\n"
            )


# 13. Finish
print("\nReports saved successfully.")
print("Files: security_report.txt and suspicious_activity.txt")