from datetime import datetime, timezone
from connector import get_mfa_devices, get_access_keys, get_user_policies, get_policy_document

def check_mfa(users, client):
    findings = []
    for user in users:
        username = user['UserName']
        mfa_devices = get_mfa_devices(client, username)
        if len(mfa_devices) == 0:
            findings.append({
                'user': username,
                'issue': 'MFA not enabled',
                'severity': 'HIGH'
            })
    return findings


def check_unused_access_keys(users, client):
    findings = []
    for user in users:
        username = user['UserName']
        access_keys = get_access_keys(client, username)
        for key in access_keys:
            if key ['Status'] == 'Active':
                key_id = key['AccessKeyId']
                last_used_response = client.get_access_key_last_used(AccessKeyId=key_id)
                last_used = last_used_response['AccessKeyLastUsed'].get('LastUsedDate')
                if last_used is None:
                    findings.append({
                        'user': username,
                        'key_id': key_id,
                        'issue': 'Active access key has never been used',
                        'severity': 'MEDIUM'
                    })
                else:
                    days_unused = (datetime.now(timezone.utc) - last_used).days
                    if days_unused > 90:
                        findings.append({
                            'user':username, 
                            'key_id': key_id, 
                            'issue': f'Access key unused for {days_unused} days',
                            'severity': 'MEDIUM'
                        })
    return findings

def check_wildcard_permissions(users, client):
    findings = []
    for user in users:
        username = user['UserName']
        policies = get_user_policies(client, username)
        for policy in policies:
            policy_arn = policy['PolicyArn']
            document = get_policy_document(client, policy_arn)
            for statement in document['Statement']:
                actions = statement.get('Action', [])
                resources = statement.get('Resource',[])    
                if isinstance(actions, str):
                    actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]
                    if '*' in actions or '*' in resources:
                        findings.append({
                            'user': username,
                            'policy': policy['PolicyName'],
                            'issue': 'Wildcard permission found (Action or Resource is *)',
                            'severity': 'HIGH'
                        })
    return findings

def check_admin_policies(users, client):
    findings = []
    admin_policies = ['AdministratorAccess', 'arn:aws:iam::aws:policy/AdministratorAccess']
    for user in users:
        username = user['UserName']
        policies = get_user_policies(client, username)
        for policy in policies:
            if policy['PolicyName'] in admin_policies or policy['PolicyArn'] in admin_policies:
                findings.append({
                    'user': username,
                    'policy': policy['PolicyName'],
                    'issue': 'Admin policy attached to non-admin user',
                    'severity': 'CRITICAL'
                })
    return findings