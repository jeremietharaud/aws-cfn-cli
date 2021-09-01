![Build](https://github.com/jeremietharaud/aws-cfn-cli/workflows/Build%20and%20test%20aws-cfn-cli/badge.svg?branch=master)
# aws-cfn-cli

This repository is used to provide a tool for deploying AWS CloudFormation stacks.

## Installation

To install `cfncli` you can either:

* Use the latest Docker image:
```
docker pull jeremietharaud/cfncli
```

* Clone the repository and install it using the following command (Python3 needed):
```
python setup.py install
```

* Install it using pip:
```
pip install git+git://github.com/jeremietharaud/aws-cfn-cli.git
```

## Running

When using Docker image, you can run `cfncli` using the following command:
```
docker run --rm -i -v $PWD:/data jeremietharaud/cfncli <arguments>
```

When using the python script directly:
```
cfncli option
```

A complete example of usage of `cfncli` in a CI/CD pipeline can be found on the following [repository](https://github.com/jeremietharaud/aws-cfn-cli-example).

## Usage

`cfncli` takes into account multiple arguments:

 * --stack-file stack-file (REQUIRED): Name or path of the CFN stack file

 * --var Key=Value : List of CFN stack parameters in key=value format and separated by comma

 * --tags Key=Value : List of CFN tags parameters in key=value format and separated by comma

 * --var-file var-file: Name or path of the file containing variables of the stack. File must be whether in Json (list of ParameterKey/ParameterValue) or in Yaml format. If Yaml file, it should contain at least one of these section: `Name`, `Tags` or `Variables`. Note that this option will override --name, --var and --tags options.

 * --name stack-name: Name of the stack to deploy. By default, it uses the stack file name (without extension)

 * --assume-role-arn: Arn of the AWS IAM role to assume for receiving temporary permissions

 * --plan: For planning changes on a CFN stack (already existing or new stack). It generates a change set and displays the changes.

 * --apply: For applying changes on a CFN stack. A change set is generated then executed.

 * --destroy: For deleting a CFN stack. It displays the list of resources that are going to be removed. `--auto-approve` option is mandatory.

 * --auto-approve: Option to be combined with `--delete` option for approving deletion of a stack.

 * --region: aame of the region to deploy the stack. If not set, it uses the region of your AWS profile.

 * --validate: Validate the syntax of the stack file.

 * --output: Displays outputs of the stack.

 * --ls: Displays the list of running Cloudformation stacks (`--stack-file` option is not mandatory in this case).

 ## Default timeout

 The default timeout for the creation/update/deletion of a stack is `30` minutes.

 The default timeout for the creation of a change set is `10` minutes (used during plan and apply options).
