import cfncli.cfncli as cfncli
import pytest
from botocore.exceptions import ParamValidationError # noqa
from moto import mock_cloudformation, mock_sts


@mock_cloudformation
def test_get_cfn_client_session() -> None:
    # Test client without assume role
    assert cfncli.get_cfn_client_session(region='eu-west-1', assume_role_arn=None) is not None


@mock_sts
def test_get_cfn_client_session_with_assume_role() -> None:
    assume_role_arn: str = "arn:aws:sts::123456789012:assumed-role/example-role/AWSCLI-Session"

    # Test client with incorrect assume role
    with pytest.raises(Exception) as excinfo:
        try:
            cfncli.get_cfn_client_session(region='eu-west-1', assume_role_arn='blabla')
        except botocore.exceptions.ParamValidationError: # noqa
            assert excinfo == 'Invalid length for parameter RoleArn, value: 6, valid range: 20-inf'

    # Test client with assume role
    assert cfncli.get_cfn_client_session(region='eu-west-1', assume_role_arn=assume_role_arn) is not None
