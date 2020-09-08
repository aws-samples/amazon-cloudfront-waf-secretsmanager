from __future__ import print_function
import json
import re
import os
import boto3
import logging
import requests
import time

from botocore.exceptions import ClientError

logger = logging.getLogger()

logger.setLevel(logging.INFO)


#======================================================================================================================
# Variables
#======================================================================================================================


WafAclName = os.environ['WAFACLNAME']
WafAclId = os.environ['WAFACLID']
WAFRulePriority = os.environ['WAFRULEPRI']
CFDistroId = os.environ['CFDISTROID']
HeaderName = os.environ['HEADERNAME']
OriginUrl = os.environ['ORIGINURL']
StackName = os.environ['STACKNAME']


#======================================================================================================================
# Helpers
#======================================================================================================================


def get_wafacl():
    client = boto3.client('wafv2')
    response = client.get_web_acl(
        Name = WafAclName,
        Scope = 'REGIONAL',
        Id = WafAclId,
        )
    return response


def update_wafacl(NewSecret, PrevSecret):
    client = boto3.client('wafv2')

    currwafrules = get_wafacl()
    locktoken = currwafrules['LockToken']

    newwafrules = [
        {
        'Name': StackName + 'XOriginVerify',
        'Priority': int(WAFRulePriority),
        'Action': {
            'Allow': {
            }
        },
        'VisibilityConfig': {
        'SampledRequestsEnabled': True,
        'CloudWatchMetricsEnabled': True,
        'MetricName': StackName + 'XOriginVerify'
        },
        'Statement': {
            'OrStatement': {
                'Statements': [
                    {
                    'ByteMatchStatement': {
                        'FieldToMatch': {
                        'SingleHeader': {
                            'Name': HeaderName
                        }
                        },
                        'PositionalConstraint': 'EXACTLY',
                        'SearchString': NewSecret,
                        'TextTransformations': [
                        {
                            'Type': 'NONE',
                            'Priority': 0
                        }
                        ]
                    }
                    },
                    {
                    'ByteMatchStatement': {
                        'FieldToMatch': {
                        'SingleHeader': {
                            'Name': HeaderName
                        }
                        },
                        'PositionalConstraint': 'EXACTLY',
                        'SearchString': PrevSecret,
                        'TextTransformations': [
                        {
                            'Type': 'NONE',
                            'Priority': 0
                        }
                        ]
                    }
                    }
                ]
                }
            }
        }
    ]

    for r in currwafrules['WebACL']['Rules']:
        if int(WAFRulePriority) != int(r['Priority']):
            newwafrules.append(r)
    
    logger.info("Update WAF WebACL Id, %s." % WafAclId)
    response = client.update_web_acl(
    Name = WafAclName,
    Scope = 'REGIONAL',
    Id = WafAclId,
    DefaultAction={
        'Block': {}
        },
    Description='CloudFront Origin Verify Sample',
    LockToken = locktoken,
    VisibilityConfig={
        'SampledRequestsEnabled': True|False,
        'CloudWatchMetricsEnabled': True|False,
        'MetricName': StackName + 'OriginVerify'
    },
    Rules = newwafrules
    )


def get_cfdistro(distroid):
    client = boto3.client('cloudfront')
    response = client.get_distribution(
        Id = distroid
        )

    return response


def get_cfdistro_config(distroid):
    client = boto3.client('cloudfront')
    response = client.get_distribution_config(
        Id = distroid
        )

    return response


def update_cfdistro(distroid, headervalue):
    
    client = boto3.client('cloudfront')
    diststatus = get_cfdistro(distroid)
    if 'Deployed' in diststatus['Distribution']['Status']:
        distconfig = get_cfdistro_config(distroid)
        headercount = 0
        #logger.info(distconfig)
        for k in distconfig['DistributionConfig']['Origins']['Items']:
            if k['CustomHeaders']['Quantity'] > 0:
                for h in k['CustomHeaders']['Items']:
                    if HeaderName in h['HeaderName']:
                        logger.info("Update custom header, %s for origin, %s." % (h['HeaderName'], k['Id']))
                        headercount = headercount + 1
                        h['HeaderValue'] = headervalue
                    
                    else:
                        logger.info("Ignore custom header, %s for origin, %s." % (h['HeaderName'], k['Id']))
                        pass

            else:
                logger.info("No custom headers found in origin, %s." % k['Id'])
                pass
        
        if headercount < 1:
            logger.error("No custom header, %s found in distribution Id, %s." % (HeaderName, distroid))
            raise ValueError("No custom header found in distribution Id, %s." % distroid)
        
        else:
            response = client.update_distribution(
                Id = distroid,
                IfMatch = distconfig['ResponseMetadata']['HTTPHeaders']['etag'],
                DistributionConfig = distconfig['DistributionConfig']
                )

            return response
                
    else:
        logger.error("Distribution Id, %s status is not Deployed." % distroid)
        raise ValueError("Distribution Id, %s status is not Deployed." % distroid)


def test_origin(url, secret):
    response = requests.get(
    url,
    headers={HeaderName: secret},
    )
    
    logger.info("Testing URL, %s - response code, %s " % (url, response.status_code))

    if response.status_code == 200:
        return True
    else:
        return False


def create_secret(service_client, arn, token):
    """Create the secret
    This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
    new secret and put it with the passed in token.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
    """
    # Make sure the current secret exists
    service_client.get_secret_value(
        SecretId=arn, 
        VersionStage="AWSCURRENT"
        )

    # Now try to get the secret version, if that fails, put a new secret
    try:
        service_client.get_secret_value(
            SecretId=arn, 
            VersionId=token, 
            VersionStage="AWSPENDING"
            )
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)

    except service_client.exceptions.ResourceNotFoundException:

        # Generate a random password
        passwd = service_client.get_random_password(
            ExcludePunctuation = True
            )

        # Put the secret
        service_client.put_secret_value(
            SecretId=arn, 
            ClientRequestToken=token, 
            SecretString='{\"HEADERVALUE\":\"%s\"}' % passwd['RandomPassword'],
            VersionStages=['AWSPENDING'])

        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, token))


def set_secret(service_client, arn, token):
    """Set the secret
    This method should set the AWSPENDING secret in the service that the secret belongs to. For example, if the secret is a database
    credential, this method should take the value of the AWSPENDING secret and set the user's password to this value in the database.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    # This is where the secret should be set in the service

    # First check to confirm CloudFront distribution is in Deployed state
    diststatus = get_cfdistro(CFDistroId)
    if 'Deployed' not in diststatus['Distribution']['Status']:
        logger.error("Distribution Id, %s status is not Deployed." % CFDistroId)
        raise ValueError("Distribution Id, %s status is not Deployed." % CFDistroId)
    
    # Obtain secret value for AWSPENDING
    pending = service_client.get_secret_value(
        SecretId=arn, 
        VersionId=token, 
        VersionStage="AWSPENDING"
        )
    
    # Obtain secret value for AWSCURRENT
    metadata = service_client.describe_secret(SecretId=arn)
    for version in metadata["VersionIdsToStages"]:
        logger.info("Getting current version %s for %s" % (version, arn))
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            currenttoken = version
            current = service_client.get_secret_value(
            SecretId=arn, 
            VersionId=currenttoken, 
            VersionStage="AWSCURRENT"
            )

    pendingsecret = json.loads(pending['SecretString'])
    currentsecret = json.loads(current['SecretString'])
    
    # Update CloudFront custom header and regional WAF WebACL rule with AWSPENDING and AWSCURRENT
    try:

        update_wafacl(pendingsecret['HEADERVALUE'], currentsecret['HEADERVALUE'])

        # Sleep for 75 seconds for regional WAF config propagation
        time.sleep(75)

        update_cfdistro(CFDistroId, pendingsecret['HEADERVALUE'])
    
    except ClientError as e:
        logger.error('Error: {}'.format(e))
        raise ValueError("Failed to update resources CloudFront Distro Id %s , WAF WebACL Id %s " % (CFDistroId, WafAclId))


def test_secret(service_client, arn, token):
    """Test the secret
    This method should validate that the AWSPENDING secret works in the service that the secret belongs to. For example, if the secret
    is a database credential, this method should validate that the user can login with the password in AWSPENDING and that the user has
    all of the expected permissions against the database.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    # This is where the secret should be tested against the service

    # Obtain secret value for AWSPENDING
    pending = service_client.get_secret_value(
    SecretId=arn, 
    VersionId=token, 
    VersionStage="AWSPENDING"
    )

    # Obtain secret value for AWSCURRENT
    metadata = service_client.describe_secret(SecretId=arn)
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            currenttoken = version
            current = service_client.get_secret_value(
            SecretId=arn, 
            VersionId=currenttoken, 
            VersionStage="AWSCURRENT"
            )
            logger.info("Getting current version %s for %s" % (version, arn))

    pendingsecret = json.loads(pending['SecretString'])
    currentsecret = json.loads(current['SecretString'])

    secrets = [pendingsecret['HEADERVALUE'], currentsecret['HEADERVALUE']]

    # Test origin URL access functional using validation headers for AWSPENDING and AWSCURRENT
    try:
        for s in secrets:
            if test_origin(OriginUrl, s):
                pass
            else:
                logger.error("Tests failed for URL, %s " % OriginUrl)
                raise ValueError("Tests failed for URL, %s " % OriginUrl)

    except ClientError as e:
        logger.error('Error: {}'.format(e))


def finish_secret(service_client, arn, token):
    """Finish the secret
    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist
    """

    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))


#======================================================================================================================
# Lambda entry point
#======================================================================================================================


def lambda_handler(event, context):

    logger.info("log -- Event: %s " % json.dumps(event))

    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    service_client = boto3.client('secretsmanager')

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s has no stage for rotation of secret %s." % (token, arn))
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (token, arn))
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))

    if step == "createSecret":
        create_secret(service_client, arn, token)

    elif step == "setSecret":
        set_secret(service_client, arn, token)

    elif step == "testSecret":
        test_secret(service_client, arn, token)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")