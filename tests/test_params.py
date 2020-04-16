import cfncli.cfncli as cfncli
import yaml
import pytest


def load_test_yaml_params() -> dict:
    with open('tests/variables.yaml', 'r') as stream:
        streams = yaml.safe_load(stream)
        return streams.get('Variables')


def load_test_tags() -> dict:
    with open('tests/variables.yaml', 'r') as stream:
        streams = yaml.safe_load(stream)
        return streams.get('Tags')


def test_to_cf_params():
    empty_params = None
    params = load_test_yaml_params()
    expected_empty_params = []
    expected_params = [{'ParameterKey': 'RepositoryName', 'ParameterValue': 'test-123'}]

    # Test empty param list
    assert cfncli.to_cf_params(empty_params) == expected_empty_params

    # Test yaml param list
    assert cfncli.to_cf_params(params) == expected_params


def test_tags_to_cf_params():
    empty_tags = None
    tags = load_test_tags()
    expected_empty_tags = []
    expected_tags = [{'Key': 'Project', 'Value': 'cfncli'}, {'Key': 'Env', 'Value': 'tst'}, {'Key': 'Name', 'Value': 'test-stack'}]

    # Test empty param list
    assert cfncli.tags_to_cf_params(empty_tags) == expected_empty_tags

    # Test tags
    assert cfncli.tags_to_cf_params(tags) == expected_tags


def test_str_tags_to_cf_params():
    empty_tags = ""
    tags = "Project=cfncli,Env=tst,Name=test-stack"
    expected_tags = [{'Key': 'Project', 'Value': 'cfncli'}, {'Key': 'Env', 'Value': 'tst'}, {'Key': 'Name', 'Value': 'test-stack'}]

    # Test empty param list
    with pytest.raises(Exception) as excinfo:
        cfncli.str_tags_to_cf_params(empty_tags)
        assert excinfo == 'dictionary update sequence element #0 has length 1; 2 is required'

    # Test tags
    assert cfncli.str_tags_to_cf_params(tags) == expected_tags


def test_str_to_cf_params():
    empty_params = ""
    params = "RepositoryName=test-123,Stack=test-stack"
    expected_params = [{'ParameterKey': 'RepositoryName', 'ParameterValue': 'test-123'}, {'ParameterKey': 'Stack', 'ParameterValue': 'test-stack'}]

    # Test empty param list
    with pytest.raises(Exception) as excinfo:
        cfncli.str_to_cf_params(empty_params)
        assert excinfo == 'dictionary update sequence element #0 has length 1; 2 is required'

    # Test params list
    assert cfncli.str_to_cf_params(params) == expected_params
