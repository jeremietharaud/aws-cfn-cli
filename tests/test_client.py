import cfncli.cfncli as cfncli
import botocore
from moto import mock_cloudformation, mock_sts


@mock_cloudformation
def test_get_cfn_client_session() -> None:
    # Test client without assume role
    client = cfncli.get_cfn_client_session(region='eu-west-3', assume_role_arn=None)
    assert client is not None
    assert client._client_config.region_name == 'eu-west-3'


@mock_sts
def test_get_cfn_client_session_with_assume_role() -> None:
    assume_role_arn: str = "arn:aws:sts::123456789012:assumed-role/example-role/AWSCLI-Session"

    # Test client with incorrect assume role
    try:
        cfncli.get_cfn_client_session(region='eu-west-3', assume_role_arn='blabla')
        assert False
    except botocore.exceptions.ParamValidationError as e:
        assert (
            "Invalid length for parameter RoleArn, value: 6, valid range: 20-inf" in str(e)
        )

    # Test client with assume role
    client = cfncli.get_cfn_client_session(region='eu-west-3', assume_role_arn=assume_role_arn)
    assert cfncli.get_cfn_client_session(region='eu-west-3', assume_role_arn=assume_role_arn) is not None
    assert client._client_config.region_name == 'eu-west-3'
