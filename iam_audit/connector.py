import boto3
def get_iam_client():
    client = boto3.client('iam')
    return client

def get_users(client):
    response = client.list_users()
    return response['Users']

def get_mfa_devices(client, user_name):
    response = client.list_mfa_devices(UserName=user_name)
    return response['MFADevices']

def get_access_keys(client, username):
    response = client.list_access_keys(UserName = username)
    return response['AccessKeyMetadata']

def get_user_policies(client, username):
    response = client.list_attached_user_policies(UserName = username)
    return response['AttachedPolicies']

def get_policy_document(client, policy_arn):
    version_response = client.get_policy(PolicyArn=policy_arn)
    version_id = version_response['Policy']['DefaultVersionId']

    document_response = client.get_policy_version(
        PolicyArn=policy_arn, 
        VersionId=version_id
    )
    return document_response['PolicyVersion']['Document']
