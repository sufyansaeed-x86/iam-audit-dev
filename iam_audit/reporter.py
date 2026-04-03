import json

def generate_report(findings, output_format='text'):
    if output_format == 'json':
        return generate_json_report(findings)
    else:
        return generate_text_report(findings)
    
def generate_text_report(findings):
    if len(findings) == 0:
        return "No findings. IAM configuration looks clean."
    
    report = "IAM AUDIT REPORT\n"
    report += "=" * 40 + "\n"

    for finding in findings:
        report += f"\n[{finding['severity']}] {finding['user']}\n"
        report += f"Issue: {finding['issue']}\n"
        if 'key_id' in finding:
            report += f"Key ID: {finding['key_id']}\n"
        if 'policy' in finding:
            report += f"Policy: {finding['policy']}\n"
        report += "-" * 40 + "\n"

    return report

def generate_json_report(findings):
    if len(findings) == 0:
        return json.dumps({'status': 'clean', 'findings': []}, indent=2)
    
    return json.dumps({'status': 'findings_found', 'total': len(findings), 'findings': findings}, indent=2)

def save_report(report, filename='iam_audit_report.txt'):
    with open(filename, 'w') as f:
        f.write(report)
    print(f"Report saved to {filename}")

    