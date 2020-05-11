import cfncli.cfncli as cfncli
import botocore
from moto import mock_cloudformation


yaml_bad_template = """"""

yaml_bad_template2 = """
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Stack that fails during planning'
"""

yaml_bad_template3 = """
AWSTemplateFormatVersion: '2010-09-09'
Transform: 'AWS::Serverless-2016-10-31'
Description: 'Stack that fails during planning'
Parameters:
  CodeURI:
    Type: String
    Description: 'URL of the lambda in S3'
Resources:
  LambdaExporter:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: !Ref CodeURI
      Handler: lambda.lambda_handler
      MemorySize: 128
      Runtime: python3.6
      Timeout: 10
"""

yaml_bad_template4 = """
AWSTemplateFormatVersion: '2010-09-09'
Transform: 'AWS::Serverless-2016-10-31'
Description: 'Stack that fails during planning'
Resources:
  LambdaExporter:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: ./code/
      Handler: lambda.lambda_handler
      MemorySize: 128
      Runtime: python3.6
      Timeout: 10
"""

yaml_valid_template = """
AWSTemplateFormatVersion: '2010-09-09'
Description: Simple CloudFormation Test Template
Resources:
  S3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: cf-test-bucket-1
"""


@mock_cloudformation
def test_create_change_set_cfn() -> None:
    client = cfncli.get_cfn_client_session(region='eu-west-1', assume_role_arn=None)

    # Test creation of change set for invalid stack
    try:
        cfncli.create_change_set_cfn(stack_name="test", template=yaml_bad_template, change_set_type='CREATE', params=None, tags=None, client=client)
        assert False
    except botocore.exceptions.ParamValidationError as e:
        assert ('Invalid length for parameter TemplateBody, value: 0, valid range: 1-inf' in str(e))

    # Test creation of change set for invalid stack
    # Does not work with @mock_cloudformation: KeyError: 'Resources'
    # try:
    #     cfncli.create_change_set_cfn(stack_name="test", template=yaml_bad_template2, change_set_type='CREATE', params=[], tags=[], client=client)
    #     assert False
    # except botocore.exceptions.ClientError as e:
    #     assert ('Template format error: At least one Resources member must be defined.' in str(e))

    # Test creation of change set for invalid stack
    try:
        cfncli.create_change_set_cfn(stack_name="test", template=yaml_bad_template3, change_set_type='CREATE', params=[], tags=[], client=client)
        assert False
    except botocore.exceptions.ClientError as e:
        assert ('An error occurred (Missing Parameter) when calling the CreateChangeSet operation: Missing parameter CodeURI' in str(e))

    # Test creation of change set for a valid stack
    change_set_id = cfncli.create_change_set_cfn(stack_name="test", template=yaml_valid_template, change_set_type='CREATE', params=[], tags=[], client=client) # noqa
    assert change_set_id is not None # noqa
    assert 'arn:aws:cloudformation:eu-west-1:123456789:changeSet/cfncli-plan-' in change_set_id
    # cleanup stack
    cfncli.delete_cfn_stack(stack_name="test", client=client, silent=True)
