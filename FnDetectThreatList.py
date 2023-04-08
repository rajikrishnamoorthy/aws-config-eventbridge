import boto3
import json
import botocore
import os

def lambda_handler(event, context):
    
        # Read the values of the location parameter
        parsed_json = json.loads(event['ruleParameters'])
        location = parsed_json['location']
        
        if location:
            
            orderingtime = json.loads(event['invokingEvent'])['notificationCreationTime']
            guardduty = boto3.client('guardduty')
            evaluations = []
            
            detectors = guardduty.list_detectors()['DetectorIds']
            
            if detectors:
                for detector in detectors:
                    response = guardduty.list_threat_intel_sets(DetectorId=detector)
                   
                    sets = response.get('ThreatIntelSetIds')
                    for set_id in sets:
                        
                        set_response = guardduty.get_threat_intel_set(DetectorId=detector, ThreatIntelSetId=set_id)
                        if set_response.get('Location') == location:
                            evaluations.append(
                            {
                                "ComplianceResourceId": detector,
                                "ComplianceResourceType": "AWS::GuardDuty::Detector",
                                "ComplianceType": "COMPLIANT",
                                "Annotation": "Threat intelligence IP address list is located at " + str(set_response.get('Location')),
                                'OrderingTimestamp': orderingtime
                            })
                        else:
                            evaluations.append(
                            {
                                "ComplianceResourceId": detector,
                                "ComplianceResourceType": "AWS::GuardDuty::Detector",
                                "ComplianceType": "NON_COMPLIANT",
                                "Annotation": "Incorrect S3 location for prohibited IP list",
                                'OrderingTimestamp': orderingtime
                                })

                        break
                        
            else:
                evaluations.append(
                    {
                        "ComplianceResourceId": detector,
                        "ComplianceResourceType": "AWS::GuardDuty::Detector",
                        "ComplianceType": "NON_COMPLIANT",
                        "Annotation": "No Threat list detected in GuardDuty",
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