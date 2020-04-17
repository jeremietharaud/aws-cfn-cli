import cfncli.cfncli as cfncli
import yaml
from typing import Dict, List
import pytest


yaml_variables = """
Name: 'test-stack'
Tags:
  Project: 'cfncli'
  Env: 'tst'
  Name: 'test-stack'
Variables:
  RepositoryName: 'test-123'
"""


def load_test_yaml_params() -> Dict[str, str]:
    streams = yaml.safe_load(yaml_variables)
    return streams.get('Variables')


def load_test_tags() -> Dict[str, str]:
    streams = yaml.safe_load(yaml_variables)
    return streams.get('Tags')


def test_to_cf_params() -> None:
    empty_params: Dict[str, str] = None
    params: Dict[str, str] = load_test_yaml_params()
    expected_empty_params: List[Dict[str, str]] = []
    expected_params: List[Dict[str, str]] = [{'ParameterKey': 'RepositoryName', 'ParameterValue': 'test-123'}]

    # Test empty param list
    assert cfncli.to_cf_params(empty_params) == expected_empty_params

    # Test yaml param list
    assert cfncli.to_cf_params(params) == expected_params


def test_tags_to_cf_params() -> None:
    empty_tags: Dict[str, str] = None
    tags: Dict[str, str] = load_test_tags()
    expected_empty_tags: List[Dict[str, str]] = []
    expected_tags: List[Dict[str, str]] = [{'Key': 'Project', 'Value': 'cfncli'}, {'Key': 'Env', 'Value': 'tst'}, {'Key': 'Name', 'Value': 'test-stack'}]

    # Test empty param list
    assert cfncli.tags_to_cf_params(empty_tags) == expected_empty_tags

    # Test tags
    assert cfncli.tags_to_cf_params(tags) == expected_tags


def test_str_tags_to_cf_params() -> None:
    empty_tags: str = ""
    tags: str = "Project=cfncli,Env=tst,Name=test-stack"
    expected_tags: List[Dict[str, str]] = [{'Key': 'Project', 'Value': 'cfncli'}, {'Key': 'Env', 'Value': 'tst'}, {'Key': 'Name', 'Value': 'test-stack'}]

    # Test empty param list
    with pytest.raises(Exception) as excinfo:
        cfncli.str_tags_to_cf_params(empty_tags)
        assert excinfo == 'dictionary update sequence element #0 has length 1; 2 is required'

    # Test tags
    assert cfncli.str_tags_to_cf_params(tags) == expected_tags


def test_str_to_cf_params() -> None:
    empty_params: str = ""
    params: str = "RepositoryName=test-123,Stack=test-stack"
    expected_params: List[Dict[str, str]] = [{'ParameterKey': 'RepositoryName', 'ParameterValue': 'test-123'}, {'ParameterKey': 'Stack', 'ParameterValue': 'test-stack'}] # noqa E501

    # Test empty param list
    with pytest.raises(Exception) as excinfo:
        cfncli.str_to_cf_params(empty_params)
        assert excinfo == 'dictionary update sequence element #0 has length 1; 2 is required'

    # Test params list
    assert cfncli.str_to_cf_params(params) == expected_params
