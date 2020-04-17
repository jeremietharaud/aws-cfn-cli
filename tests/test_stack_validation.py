import cfncli.cfncli as cfncli
import pytest
import tempfile
import os
from botocore.exceptions import ParamValidationError # noqa
from botocore import client as Client
from moto import mock_cloudformation


yaml_bad_template = """
"""

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


@mock_cloudformation
def test_validate_cfn_stack() -> None:
    client: Client = cfncli.get_cfn_client_session(region='eu-west-1', assume_role_arn=None)

    # Test validation of invalid stack
    with pytest.raises(Exception) as excinfo:
        try:
            cfncli.validate_cfn_stack(template=yaml_bad_template, client=client)
        except botocore.exceptions.ParamValidationError: # noqa
            assert excinfo == 'Invalid length for parameter TemplateBody, value: 0, valid range: 1-inf'

    # Test validation of invalid stack
    with pytest.raises(Exception) as excinfo:
        try:
            cfncli.validate_cfn_stack(template=yaml_bad_template2, client=client)
        except botocore.exceptions.ParamValidationError: # noqa
            assert excinfo == 'Template format error: At least one Resources member must be defined.'

    # Test validation of valid stack
    assert cfncli.validate_cfn_stack(template=yaml_valid_template, client=client) is None


@mock_cloudformation
def test_validate() -> None:
    client: Client = cfncli.get_cfn_client_session(region='eu-west-1', assume_role_arn=None)

    # Test validation of invalid stack
    file_descriptor1, yaml_bad_template_file = tempfile.mkstemp()
    with open(yaml_bad_template_file, "w") as f:
        f.write(yaml_bad_template)
    with pytest.raises(Exception) as excinfo:
        try:
            cfncli.validate(stack_name="test", stack_file=yaml_bad_template_file, client=client)
        except botocore.exceptions.ParamValidationError: # noqa
            assert excinfo == 'Invalid length for parameter TemplateBody, value: 0, valid range: 1-inf'
    os.close(file_descriptor1)
    os.remove(yaml_bad_template_file)

    # Test validation of invalid stack
    file_descriptor2, yaml_bad_template_file2 = tempfile.mkstemp()
    with open(yaml_bad_template_file2, "w") as f:
        f.write(yaml_bad_template2)
    with pytest.raises(Exception) as excinfo:
        try:
            cfncli.validate(stack_name="test", stack_file=yaml_bad_template_file2, client=client)
        except botocore.exceptions.ParamValidationError: # noqa
            assert excinfo == 'Template format error: At least one Resources member must be defined.'
    os.close(file_descriptor2)
    os.remove(yaml_bad_template_file2)

    # Test validation of valid stack
    file_descriptor3, yaml_valid_template_file = tempfile.mkstemp()
    with open(yaml_valid_template_file, "w") as f:
        f.write(yaml_valid_template)
    assert cfncli.validate(stack_name="test", stack_file=yaml_valid_template_file, client=client) is None
    os.close(file_descriptor3)
    os.remove(yaml_valid_template_file)
