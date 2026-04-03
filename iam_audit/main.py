import argparse
from connector import get_iam_client, get_users
from checks import check_mfa, check_unused_access_keys, check_wildcard_permissions, check_admin_policies
from reporter import generate_report, save_report

def main():
    parser = argparse.ArgumentParser(description='IAM Audit Tool')
    parser.add_argument('--format', choices=['text', 'json'], default='text', help='Output format for the report')
    parser.add_argument('--output', default='iam_audit_report.txt', help='Output filename for the report')
    args = parser.parse_args()

print("Connecting to AWS...")
client = get_iam_client()

print("Fetching IAM user...")
users = get_users(client)
print(f"Found {len(users)} users")

print("Running security checks...")
findings = []
findings += check_mfa(users, client)
findings += check_unused_access_keys(users, client)
findings += check_wildcard_permissions(users, client)
findings += check_admin_policies(users, client)
print(f"Found {len(findings)} findings")

