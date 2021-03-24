import cfncli.cfncli as cfncli
import tempfile
import os
import botocore
from moto import mock_cloudformation


yaml_bad_template = """"""

yaml_bad_template2 = """
AWSTemplateFormatVersion: '2010-09-09'
Description: Simple CloudFormation Test Template
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

# yaml_valid_template = """
# AWSTemplateFormatVersion: 2010-09-09
# Description: 'Test stack that works'
# Parameters:
#     RepositoryName:
#       Description: 'Name of the ECR repository'
#       Type: String
# Resources:
#   TestEcrRepository:
#     Type: 'AWS::ECR::Repository'
#     Properties:
#       RepositoryName: !Ref RepositoryName
# """


@mock_cloudformation
def test_validate_cfn_stack() -> None:
    client = cfncli.get_cfn_client_session(region='eu-west-1', assume_role_arn=None)

    # Test validation of invalid stack
    try:
        cfncli.validate_cfn_stack(template=yaml_bad_template, client=client)
        assert False
    except botocore.exceptions.ParamValidationError as e:
        assert ('Parameter validation failed:\nInvalid length for parameter TemplateBody, value: 0, valid min length: 1' in str(e))

    # Test validation of invalid stac
    try:
        cfncli.validate_cfn_stack(template=yaml_bad_template2, client=client)
        assert False
    except botocore.exceptions.ClientError as e:
        assert ('Stack with id Missing top level item Resources to file module does not exist' in str(e))

    # Test validation of valid stack
    assert cfncli.validate_cfn_stack(template=yaml_valid_template, client=client) is None


@mock_cloudformation
def test_validate() -> None:
    client = cfncli.get_cfn_client_session(region='eu-west-1', assume_role_arn=None)

    # Test validation of invalid stack
    file_descriptor1, yaml_bad_template_file = tempfile.mkstemp()
    with open(yaml_bad_template_file, "w") as f:
        f.write(yaml_bad_template)
    try:
        cfncli.validate(stack_name="test", stack_file=yaml_bad_template_file, client=client)
        assert False
    except botocore.exceptions.ParamValidationError as e:
        assert ('Parameter validation failed:\nInvalid length for parameter TemplateBody, value: 0, valid min length: 1' in str(e))
    os.close(file_descriptor1)
    os.remove(yaml_bad_template_file)

    # Test validation of invalid stack
    file_descriptor2, yaml_bad_template_file2 = tempfile.mkstemp()
    with open(yaml_bad_template_file2, "w") as f:
        f.write(yaml_bad_template2)
    try:
        cfncli.validate(stack_name="test", stack_file=yaml_bad_template_file2, client=client)
    except botocore.exceptions.ClientError as e:
        assert ('Stack with id Missing top level item Resources to file module does not exist' in str(e))
    os.close(file_descriptor2)
    os.remove(yaml_bad_template_file2)

    # Test validation of valid stack
    file_descriptor3, yaml_valid_template_file = tempfile.mkstemp()
    with open(yaml_valid_template_file, "w") as f:
        f.write(yaml_valid_template)
    assert cfncli.validate(stack_name="test", stack_file=yaml_valid_template_file, client=client) is None
    os.close(file_descriptor3)
    os.remove(yaml_valid_template_file)
