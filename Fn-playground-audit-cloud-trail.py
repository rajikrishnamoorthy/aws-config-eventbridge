import json
import boto3
import os

def lambda_handler(event, context):
    accountid = event['account']    
    
    s3_bucket = os.environ['s3_bucket']
    trail_name = os.environ['trail_name']
    
    cloudtrail_client = boto3.client('cloudtrail')
    sns_client = boto3.client('sns')
    
    trail = cloudtrail_client.describe_trails(
        trailNameList=[trail_name]
    )
    trail_arn = trail['trailList'][0]['TrailARN']
    logging_status = check_cloudtrail_logging_status(trail_arn,cloudtrail_client)
    print(logging_status)
   
    if logging_status:
        print("CloudTrail logging is ON.")
    else:
        print("CloudTrail logging is OFF.")
    
    if(logging_status):
        if trail and trail.get('trailList',[]):
            trail_desc = trail['trailList'][0]
    
            if trail_desc['S3BucketName'] != s3_bucket:
                cloudtrail_client.update_trail(
                    Name = trail_name,
                    S3BucketName = s3_bucket
                )
                sns_client.publish(
                  TopicArn=os.getenv('topic_arn'),
                  Message='Bucket Name was Wrong, Corrected Bucket Name on CLoudTrail',
                  Subject='S3 Bucket on CloudTrail Misconfigured'
                )
            elif 'CloudWatchLogsLogGroupArn' not in trail_desc:
                update_cloudwatch(cloudtrail_client,sns_client)
            elif trail_desc['CloudWatchLogsLogGroupArn'] != 'arn:aws:logs:ap-south-1:{}:log-group:Playground-Labs-cloudwatch:*'.format(accountid):
                update_cloudwatch(cloudtrail_client,sns_client)
            else:
                print('All Good')
        else:
            cloudtrail_client.create_trail(
                Name= trail_name,
                S3BucketName= s3_bucket,
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True,
                CloudWatchLogsLogGroupArn='arn:aws:logs:ap-south-1:453010743624:log-group:Playground-Labs-Cloudwatch:*',
                CloudWatchLogsRoleArn='arn:aws:iam::453010743624:role/Playground-cloud-trail-full-access'
            )
            sns_client.publish(
                TopicArn=os.getenv('topic_arn'),
                Message='No CloudTrail, Created a New Trail to Standard',
                Subject='CloudTrail Didnt Exist'
            )
            
    else:
        switchONCloudTrail(trail_arn,cloudtrail_client,sns_client)
    
    
                
def update_cloudwatch(cloudtrail_client,sns_client):
    my_session = boto3.session.Session()
    my_region = my_session.region_name
    print("update_cloudwatch() is executed")
    
    cloudtrail_client.update_trail(
        Name='playground-labs',
        CloudWatchLogsLogGroupArn='arn:aws:logs:ap-south-1:453010743624:log-group:Playground-Labs-Cloudwatch:*',
        CloudWatchLogsRoleArn='arn:aws:iam::453010743624:role/Playground-cloud-trail-full-access'
    )
    sns_client.publish(
        TopicArn=os.getenv('topic_arn'),
        Message='CloudWatch Log Group not Configured, Updated Trail with CloudWatch',
        Subject='CloudWatch Group on CloudTrail Misconfigured'
    )

def check_cloudtrail_logging_status(trail_arn,cloudtrail_client):
    status = cloudtrail_client.get_trail_status(
        Name=trail_arn
    )
    return status['IsLogging']

def switchONCloudTrail(trail_arn,cloudtrail_client,sns_client):
    cloudtrail_client.start_logging(
        Name=trail_arn
    )
    print("CloudTrail logging has been turned ON.")
    sns_client.publish(
        TopicArn=os.getenv('topic_arn'),
        Message='CloudTrail Enabled Rule Misconfiguration',
        Subject='CloudTrail logging was turned OFF, we have fixed it now!'
    )

