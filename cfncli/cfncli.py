import argparse
import logging
import datetime
import time
import json
import yaml
import os
from typing import List, Tuple, Dict

import boto3
from botocore.exceptions import ClientError, ParamValidationError
from botocore import client as Client
try:
    from cfncli import __version__ as version
except ImportError:
    from __init__ import __version__ as version

__version__ = version

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)

cfn_status_create_complete_list = ['CREATE_FAILED', 'CREATE_COMPLETE', 'UPDATE_COMPLETE', 'ROLLBACK_IN_PROGRESS',
                                   'ROLLBACK_FAILED', 'ROLLBACK_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE',
                                   'UPDATE_ROLLBACK_IN_PROGRESS', 'UPDATE_ROLLBACK_FAILED',
                                   'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS']
cfn_stack_status_error_list = ['CREATE_FAILED', 'ROLLBACK_IN_PROGRESS', 'UPDATE_ROLLBACK_IN_PROGRESS',
                               'ROLLBACK_FAILED', 'ROLLBACK_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE',
                               'UPDATE_ROLLBACK_FAILED', 'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS']


def to_cf_params(params: Dict[str, str]) -> List[Dict[str, str]]:
    if params is not None:
        return [{'ParameterKey': k, 'ParameterValue': v} for (k, v) in params.items()]
    else:
        return []


def str_to_cf_params(params: str) -> List[Dict[str, str]]:
    dict_params: Dict[str, str] = dict(kv.split("=") for kv in params.split(","))
    if params is not None:
        return [{'ParameterKey': k, 'ParameterValue': v} for (k, v) in dict_params.items()]
    else:
        return []


def tags_to_cf_params(tags: Dict[str, str]) -> List[Dict[str, str]]:
    if tags is not None:
        return [{'Key': k, 'Value': v} for (k, v) in tags.items()]
    else:
        return []


def str_tags_to_cf_params(tags: str) -> List[Dict[str, str]]:
    dict_tags: Dict[str, str] = dict(kv.split("=") for kv in tags.split(","))
    if dict_tags is not None:
        return [{'Key': k, 'Value': v} for (k, v) in dict_tags.items()]
    else:
        return []


def get_cfn_client_session(region: str, assume_role_arn: str) -> Client:
    if assume_role_arn is not None:
        sts_client: Client = boto3.client('sts', region_name=region)
        try:
            assumed_role_object = sts_client.assume_role(
                RoleArn=assume_role_arn,
                RoleSessionName="AssumeRoleSession1"
            )
            credentials = assumed_role_object['Credentials']
            client: Client = boto3.client(
                'cloudformation',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
        except ClientError as e:
            logger.error(e.response.get("Error").get("Message"))
            raise
        except ParamValidationError as e:
            logger.error(e)
            raise
        except Exception as e:
            logger.error(e)
            raise
    else:
        try:
            client: Client = boto3.client('cloudformation', region_name=region)
        except ClientError as e:
            logger.error(e.response.get("Error").get("Message"))
            raise
        except ParamValidationError as e:
            logger.error(e)
            raise
        except Exception as e:
            logger.error(e)
            raise
    return client


def validate_cfn_stack(template: str, client: Client) -> None:
    try:
        client.validate_template(TemplateBody=template)
    except ClientError as e:
        raise e
    except ParamValidationError as e:
        logger.error(e)
        raise
    except Exception as e:
        logger.error(e)
        raise


def create_change_set_cfn(stack_name: str, template: str, client: Client, change_set_type: str, params: List[Dict[str, str]], tags: List[Dict[str, str]]) -> str: # noqa E501
    change_set_name: str = 'cfncli-plan-' + datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")
    logger.info(f"Change set name: {change_set_name}")
    change_set = client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template,
        Parameters=params,
        Tags=tags,
        ChangeSetType=change_set_type,
        Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM', 'CAPABILITY_AUTO_EXPAND']
    )
    try:
        wait_creation_change_set_cfn(stack_name=stack_name, change_set_name=change_set_name, client=client, timeout=600)
    except ClientError as e:
        raise e
    return change_set['Id']


def describe_change_set_cfn(stack_name: str, client: Client, change_set_name: str) -> Tuple:
    change_set = client.describe_change_set(StackName=stack_name, ChangeSetName=change_set_name)
    return change_set['Changes'], change_set['ExecutionStatus']


def wait_creation_change_set_cfn(stack_name: str, change_set_name: str, client: Client, timeout: int) -> None:
    # Wait fastly
    for x in range(0, 8):
        stack = client.describe_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        stack_status = stack['Status']
        if stack_status in ['CREATE_COMPLETE', 'FAILED']:
            break
        time.sleep(1)
    if stack_status == 'CREATE_COMPLETE':
        return
    else:
        if 'StatusReason' in stack:
            if "The submitted information didn't contain changes" in str(stack['StatusReason']):
                return
            else:
                error_response = {'Error': {'Code': 'ValidationException', 'Message': stack['StatusReason']}}
                raise ClientError(error_response, 'CreateChangeSet')
    # Wait slowly
    for x in range(1, int(timeout/10)):
        logger.info(f"Creation of the change set in progress... ({x}0 seconds)")
        stack = client.describe_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        stack_status = stack['Status']
        if stack_status in ['CREATE_COMPLETE', 'FAILED']:
            break
        time.sleep(10)
    if stack_status == 'CREATE_COMPLETE':
        return
    else:
        if 'StatusReason' in stack:
            if "The submitted information didn't contain changes" in str(stack['StatusReason']):
                return
            else:
                error_response = {'Error': {'Code': 'ValidationException', 'Message': stack['StatusReason']}}
                raise ClientError(error_response, 'CreateChangeSet')
        else:
            logger.error("Timeout error")
            raise


def execute_change_set_cfn(stack_name: str, client: Client, change_set_name: str) -> None:
    client.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
    try:
        wait_creation_change_set_cfn(stack_name=stack_name, change_set_name=change_set_name, client=client, timeout=600)
    except ClientError as e:
        logger.error(e)
        raise


def delete_change_set_cfn(stack_name: str, client: Client, change_set_name: str) -> None:
    client.delete_change_set(StackName=stack_name, ChangeSetName=change_set_name)


def get_cfn_stack(stack_name: str, client: Client) -> Dict[str, str]:
    try:
        stack = client.describe_stacks(StackName=stack_name)
        return stack['Stacks'][0]
    except ClientError as e:
        if 'does not exist' in str(e):
            return None
        else:
            raise e


def describe_cfn_stack_resources(stack_name: str, client: Client) -> List[Dict[str, str]]:
    resources = client.describe_stack_resources(StackName=stack_name)['StackResources']
    for resource in resources:
        del resource['Timestamp']
        del resource['DriftInformation']
        del resource['StackId']
        del resource['StackName']
        del resource['ResourceStatus']
    return resources


def wait_create_or_update_cfn_stack(stack_name: str, client: Client, timeout: int, operation: str) -> None:
    # Wait fastly
    for x in range(1, 10):
        logger.info(f"{operation} in progress... ({x} seconds)")
        stack: Dict[str, str] = get_cfn_stack(stack_name=stack_name, client=client)
        if stack is None:
            logger.error(f"Stack '{stack_name}' not found in {client._client_config.region_name}")
            raise
        stack_status: str = stack['StackStatus']
        if stack_status in cfn_status_create_complete_list:
            break
        time.sleep(1)
    if stack_status in cfn_stack_status_error_list:
        if 'StackStatusReason' in stack:
            logger.error(stack['StackStatusReason'])
        else:
            logger.error(f"{operation} has failed...")
        wait_rollback_cfn_stack(stack_name=stack_name, client=client, timeout=timeout)
        raise
    if stack_status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
        return
    # Wait slowly
    for x in range(1, int(timeout/10)):
        logger.info(f"{operation} in progress... ({x}0 seconds)")
        stack: Dict[str, str] = get_cfn_stack(stack_name=stack_name, client=client)
        if stack is None:
            logger.error("Stack no found.")
            raise
        stack_status: str = stack['StackStatus']
        if stack_status in cfn_status_create_complete_list:
            break
        time.sleep(10)
    if stack_status in cfn_stack_status_error_list:
        if 'StackStatusReason' in stack:
            logger.error(stack['StackStatusReason'])
        else:
            logger.error(f"{operation} has failed...")
        wait_rollback_cfn_stack(stack_name=stack_name, client=client, timeout=timeout)
        raise
    if stack_status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
        return
    else:
        logger.error("Timeout error")
        raise


def wait_rollback_cfn_stack(stack_name: str, client: Client, timeout: int) -> None:
    # Wait fastly
    for x in range(1, 10):
        logger.info(f"Rollback in progress... ({x} seconds)")
        stack: Dict[str, str] = get_cfn_stack(stack_name=stack_name, client=client)
        if stack is None:
            logger.info("Rollback complete.")
            return
        stack_status: str = stack['StackStatus']
        if stack_status in ['UPDATE_ROLLBACK_FAILED', 'UPDATE_ROLLBACK_COMPLETE', 'ROLLBACK_COMPLETE']:
            break
        time.sleep(1)
    if stack_status in ['UPDATE_ROLLBACK_FAILED']:
        logger.error("Rollback of the stack has failed. Please check on the AWS console.")
        return
    if stack_status in ['UPDATE_ROLLBACK_COMPLETE']:
        logger.info("Rollback complete.")
        return
    if stack_status in ['ROLLBACK_COMPLETE']:
        logger.info('Rollback complete. Note that cfncli does not remove rollbacked stack, it has ' +
                    'to be removed first before being re-deployed.')
        return
    # Wait slowly
    for x in range(1, int(timeout/10)):
        logger.info(f"Rollback in progress... ({x}0 seconds)")
        stack: Dict[str, str] = get_cfn_stack(stack_name=stack_name, client=client)
        if stack is None:
            return
        stack_status: str = stack['StackStatus']
        if stack_status in ['UPDATE_ROLLBACK_FAILED', 'UPDATE_ROLLBACK_COMPLETE', 'ROLLBACK_COMPLETE']:
            break
        time.sleep(10)
    if stack_status in ['UPDATE_ROLLBACK_FAILED']:
        logger.error("Rollback of the stack has failed. Please check on the AWS console.")
        return
    if stack_status in ['UPDATE_ROLLBACK_COMPLETE']:
        logger.info("Rollback complete.")
        return
    if stack_status in ['ROLLBACK_COMPLETE']:
        logger.info('Rollback complete. Note that cfncli does not remove rollbacked stack, it has ' +
                    'to be removed first before being re-deployed.')
        return
    else:
        logger.error("Timeout error")
        raise


def wait_deletion_cfn_stack(stack_name: str, client: Client, timeout: int, silent: bool) -> None:
    # Wait fastly
    for x in range(1, 10):
        if not silent:
            logger.info(f"Deletion in progress... ({x} seconds)")
        stack: Dict[str, str] = get_cfn_stack(stack_name=stack_name, client=client)
        if stack is None:
            return
        stack_status: str = stack['StackStatus']
        if stack_status in ['DELETE_FAILED', 'DELETE_COMPLETE']:
            break
        time.sleep(1)
    if stack_status == 'DELETE_FAILED':
        logger.error(stack['StackStatusReason'])
        raise
    if stack_status == 'DELETE_COMPLETE':
        return
    # Wait slowly
    for x in range(1, int(timeout/10)):
        if not silent:
            logger.info(f"Deletion in progress... ({x}0 seconds)")
        stack: Dict[str, str] = get_cfn_stack(stack_name=stack_name, client=client)
        if stack is None:
            return
        stack_status: str = stack['StackStatus']
        if stack_status in ['DELETE_FAILED', 'DELETE_COMPLETE']:
            break
        time.sleep(10)
    if stack_status == 'DELETE_FAILED':
        logger.error(stack['StackStatusReason'])
        raise
    if stack_status == 'DELETE_COMPLETE':
        return
    else:
        logger.error("Timeout error")
        raise


def delete_cfn_stack(stack_name: str, client: Client, silent: bool) -> None:
    stack: Dict[str, str] = get_cfn_stack(stack_name=stack_name, client=client)
    if stack is not None:
        client.delete_stack(StackName=stack_name)
        wait_deletion_cfn_stack(stack_name=stack_name, client=client, timeout=1800, silent=silent)


def display_outputs(stack_name: str, client: Client) -> None:
    try:
        stack: Dict[str, str] = get_cfn_stack(stack_name=stack_name, client=client)
    except ClientError as e:
        logger.error(e.response.get("Error").get("Message"))
        raise
    except Exception as e:
        logger.error(e)
        raise
    if stack is None:
        logger.error(f"Stack '{stack_name}' not found in {client._client_config.region_name}")
        raise
    if 'Outputs' in stack:
        outputs: List[Dict[str, str]] = stack['Outputs']
        output_list = ''
        for output in outputs:
            output_list += '   %s = %s' % (output['ExportName'], output['OutputValue'])
        logger.info(f"\nOutputs:\n\n{output_list}")


def list_running_stacks(client: Client) -> None:
    try:
        client.describe_stacks()
        stacks_iterator = client.get_paginator('describe_stacks').paginate()
    except ClientError as e:
        logger.error(e.response.get("Error").get("Message"))
        raise
    except Exception as e:
        logger.error(e)
        raise
    list_running_stacks = ''
    for stacks in stacks_iterator:
        for stack in stacks['Stacks']:
            list_running_stacks += '%s | %s\n' % (stack['StackName'], stack['StackStatus'])
    logger.info(f"Cloudformation stacks in {client._client_config.region_name}:\n{list_running_stacks}")


def validate(stack_name: str,  stack_file: str, client: Client) -> None:
    logger.info(f"Starting validation of the stack '{stack_name}' in {client._client_config.region_name}")
    with open(stack_file, 'r') as template:
        try:
            validate_cfn_stack(template=template.read(), client=client)
        except ClientError as e:
            logger.error(e.response.get("Error").get("Message"))
            raise
        except Exception as e:
            logger.error(e)
            raise
        logger.info("Stack validated")


def plan(stack_name: str,  stack_file: str, client: Client, params: List[Dict[str, str]], tags: List[Dict[str, str]], keep_plan: bool) -> Tuple:
    logger.info(f"Starting plan of the stack '{stack_name}' in {client._client_config.region_name}")
    try:
        stack: Dict[str, str] = get_cfn_stack(stack_name=stack_name, client=client)
    except ClientError as e:
        logger.error(e.response.get("Error").get("Message"))
        raise
    except Exception as e:
        logger.error(e)
        raise
    if stack is None:
        change_set_type: str = 'CREATE'
    else:
        change_set_type: str = 'UPDATE'
    with open(stack_file, 'r') as template:
        try:
            change_set = create_change_set_cfn(
                stack_name=stack_name,
                template=template.read(),
                client=client,
                change_set_type=change_set_type,
                params=params,
                tags=tags
            )
        except ClientError as e:
            logger.error(e)
            if stack is None:
                delete_cfn_stack(stack_name=stack_name, client=client, silent=True)
            raise
        change_list, execution_status = describe_change_set_cfn(stack_name=stack_name, client=client, change_set_name=change_set)
        if execution_status == 'AVAILABLE':
            logger.info("List of changes:")
            logger.info('\n' + json.dumps(change_list, indent=4, sort_keys=True))
            if keep_plan:
                return change_set, change_set_type
        else:
            logger.info("No change detected")
        delete_change_set_cfn(stack_name=stack_name, client=client, change_set_name=change_set)
        if stack is None:
            delete_cfn_stack(stack_name=stack_name, client=client, silent=True)
        return None, change_set_type


def apply(stack_name: str, change_set_name: str, change_set_type: str, client: Client, auto_approve: bool) -> None:
    if change_set_type == 'CREATE':
        logger.info(f"Starting creation of the stack '{stack_name}' in {client._client_config.region_name}")
        execute_change_set_cfn(stack_name=stack_name, change_set_name=change_set_name, client=client)
        wait_create_or_update_cfn_stack(stack_name=stack_name, client=client, timeout=1800, operation='Creation')
        logger.info("Stack created")
    else:
        logger.info(f"Starting update of the stack '{stack_name}' in {client._client_config.region_name}")
        execute_change_set_cfn(stack_name=stack_name, change_set_name=change_set_name, client=client)
        wait_create_or_update_cfn_stack(stack_name=stack_name, client=client, timeout=1800, operation='Update')
        logger.info("Stack updated")


def destroy(stack_name: str, client: Client, auto_approve: bool) -> None:
    logger.info(f"Starting deletion of the stack '{stack_name}' in {client._client_config.region_name}")
    try:
        stack: Dict[str, str] = get_cfn_stack(stack_name=stack_name, client=client)
    except ClientError as e:
        logger.error(e.response.get("Error").get("Message"))
        raise
    if stack is not None:
        resources: List[Dict[str, str]] = describe_cfn_stack_resources(stack_name=stack_name, client=client)
        logger.info("The following resources are going to be removed:")
        logger.info('\n' + json.dumps(resources, indent=4, sort_keys=True))
        if auto_approve:
            delete_cfn_stack(stack_name=stack_name, client=client, silent=False)
            logger.info("Stack deleted")
        else:
            logger.info("Auto-approve is missing. The stack will not be deleted.")
    else:
        logger.info("Stack does not exist or is already deleted, nothing to do")


# Extension of argparse.Action class
class ListRunningStacks(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        super(ListRunningStacks, self).__init__(option_strings, dest, nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            client: Client = get_cfn_client_session(region=namespace.region, assume_role_arn=namespace.assume_role_arn)
            list_running_stacks(client=client)
        except Exception:
            exit(1)
        exit(0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-v', '--version', action='version',
        version=__version__, help="Show cfncli's version number and exit.")
    parser.add_argument(
        '--region', metavar='<REGION>', default=os.environ.get('AWS_REGION'), type=str,
        help='Name of the AWS region to deploy/update/destroy the stack')
    parser.add_argument(
        '--stack-file', metavar='<STACK FILE>', type=str,
        required=True, help='Name of the stack file containing JSON or YAML code')
    parser.add_argument(
        '--var-file', metavar='<VAR FILE>', type=str,
        required=False, help='Name of the file containing name, parameters and tags of the stack')
    parser.add_argument(
        '--name', metavar='<STACK NAME>', type=str,
        required=False, help='Name of the stack to deploy')
    parser.add_argument(
        '--tags', metavar='<TAG LIST>', type=str,
        required=False, help='List of stack tags to apply in key=value format')
    parser.add_argument(
        '--var', metavar='<VAR LIST>', type=str,
        required=False, help='List of stack parameters in key=value format')
    parser.add_argument(
        '--assume-role-arn', metavar='<ASSUMEROLE ARN>', type=str,
        required=False, help='Arn of the role to assume')
    parser.add_argument('--validate', action="store_true", help='Validate the stack')
    parser.add_argument('--plan', action="store_true", help='Planning of the deployment')
    parser.add_argument('--apply', action="store_true", help='Launch the deployment of the stack')
    parser.add_argument('--destroy', action="store_true", help='Launch the deletion of the stack')
    parser.add_argument('--auto-approve', action="store_true", help='Auto approve the deployment')
    parser.add_argument('--output', action="store_true", help='Show stack output')
    parser.add_argument('--ls', action=ListRunningStacks, help='List running CloudFormation stacks', nargs=0)

    args = parser.parse_args()

    try:
        with open(args.stack_file, 'r') as stream:
            pass
    except Exception as e:
        logger.error(e)
        exit(1)

    if args.name:
        stack_name = args.name
    else:
        stack_name = os.path.splitext(str(args.stack_file))[0]

    if args.tags:
        try:
            tags = str_tags_to_cf_params(tags=args.tags)
        except Exception as e:
            logger.error(e)
            exit(1)
    else:
        tags = []

    if args.var_file:
        try:
            with open(args.var_file, 'r') as stream:
                try:
                    streams = yaml.safe_load(stream)
                except yaml.YAMLError as e:
                    raise e
                if isinstance(streams, list):
                    params = streams
                else:
                    name = streams.get('Name')
                    if name is not None:
                        stack_name = name
                    params = to_cf_params(params=streams.get('Variables'))
                    tags = tags_to_cf_params(tags=streams.get('Tags'))
        except Exception as e:
            logger.error(e)
            exit(1)
    else:
        if args.var:
            try:
                params = str_to_cf_params(params=args.var)
            except Exception as e:
                logger.error(e)
                exit(1)
        else:
            params = []

    if args.validate:
        try:
            client: Client = get_cfn_client_session(region=args.region, assume_role_arn=args.assume_role_arn)
            validate(stack_name=stack_name, stack_file=args.stack_file, client=client)
        except Exception:
            exit(1)
        exit(0)

    if args.plan:
        try:
            client: Client = get_cfn_client_session(region=args.region, assume_role_arn=args.assume_role_arn)
            validate(stack_name=stack_name, stack_file=args.stack_file, client=client)
            plan(stack_name=stack_name, stack_file=args.stack_file, client=client, keep_plan=False, params=params, tags=tags)
        except Exception:
            exit(1)
        exit(0)

    if args.apply:
        try:
            client: Client = get_cfn_client_session(region=args.region, assume_role_arn=args.assume_role_arn)
            (change_set, change_set_type) = plan(stack_name=stack_name, stack_file=args.stack_file, client=client, keep_plan=True, params=params, tags=tags)
            if change_set is not None:
                apply(stack_name=stack_name, change_set_name=change_set, change_set_type=change_set_type, client=client, auto_approve=args.auto_approve)
            display_outputs(stack_name=stack_name, client=client)
        except Exception:
            exit(1)
        exit(0)

    if args.output:
        try:
            client: Client = get_cfn_client_session(region=args.region, assume_role_arn=args.assume_role_arn)
            display_outputs(stack_name=stack_name, client=client)
        except Exception:
            exit(1)
        exit(0)

    if args.destroy:
        try:
            client: Client = get_cfn_client_session(region=args.region, assume_role_arn=args.assume_role_arn)
            destroy(stack_name=stack_name, auto_approve=args.auto_approve, client=client)
        except Exception:
            exit(1)
        exit(0)

    parser.print_help()


if __name__ == "__main__":
    main()
