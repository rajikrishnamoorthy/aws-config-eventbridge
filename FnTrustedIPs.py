import boto3
import json
import os

def lambda_handler(event, context):
       
        
        # Extract the input parameters
        input_parameters = json.loads(event["ruleParameters"])
        # Read the values of the location parameter
        s3_url = input_parameters["location"]
        #s3_url = 'https://myorganization-trusted-list.s3.ap-southeast-2.amazonaws.com/trusted-IP-list.txt'
        orderingtime = json.loads(event['invokingEvent'])['notificationCreationTime']
        
        guardduty = boto3.client('guardduty')
        
        # Get a list of detectors
        detectors = guardduty.list_detectors()['DetectorIds']
        if not detectors:
            print("No GuardDuty detectors found.")
            return
        evaluations = []
        
        
        for detector in detectors:
            # Fetch all IP set IDs for the detector
            response = guardduty.list_ip_sets(DetectorId=detector)
            ip_set_ids = response.get('IpSetIds', [])
    
            # Loop through each IP set ID
            for ip_set_id in ip_set_ids:
                try:
                    ip_set = guardduty.get_ip_set(DetectorId=detector, IpSetId=ip_set_id)
                    print("testing#1")
                    print(str(ip_set['Location']))
                    if (str(ip_set['Location']) == str(s3_url)):
                        evaluations.append(
                            {
                                "ComplianceResourceId": detector,
                                "ComplianceResourceType": "AWS::GuardDuty::Detector",
                                "ComplianceType": "COMPLIANT",
                                "Annotation": "The trusted IPs S3 location is correct",
                                'OrderingTimestamp': orderingtime
                            })
                        break
                    else:
                         evaluations.append(
                            {
                                "ComplianceResourceId": detector,
                                "ComplianceResourceType": "AWS::GuardDuty::Detector",
                                "ComplianceType": "NON_COMPLIANT",
                                "Annotation": "Incorrect S3 location for trusted IPs or there is an error",
                                'OrderingTimestamp': orderingtime
                                })
                   
                except Exception as e:
                     evaluations.append(
                            {
                                "ComplianceResourceId": detector,
                                "ComplianceResourceType": "AWS::GuardDuty::Detector",
                                "ComplianceType": "NON_COMPLIANT",
                                "Annotation": "Error in reading trusted ip list in Guardduty",
                                'OrderingTimestamp': orderingtime
                                })
                    
  
        # Return the evaluation result
        result_token = event['resultToken']
        config = boto3.client('config')
        response = config.put_evaluations(
                Evaluations = evaluations,
                ResultToken = result_token,
                TestMode = False
                )

    
   