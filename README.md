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
docker run --rm -i -e AWS_ACCESS_KEY_ID=<access_key> -e AWS_SECRET_ACCESS_KEY=<secret_key> -e AWS_REGION=<region> -v $PWD:/data jeremietharaud/cfncli cfncli
```

When using the python script directly:
```
cfncli option
```

## Usage

`cfncli` takes into account multiple arguments:

 * --stack-file stack-file (REQUIRED): name or path of the CFN stack file

 * --var Key=Value : list of CFN stack parameters in key=value format and separated by comma

 * --tags Key=Value : list of CFN tags parameters in key=value format and separated by comma

 * --var-file var-file: name or path of the file containing variables of the stack. File must be whether in Json (list of ParameterKey/ParameterValue) or in Yaml format. If Yaml file, it should contain at least one of these section: `Name`, `Tags` or `Variables`. Note that this option will override --name, --var and --tags options.

 * --name stack-name: name of the stack to deploy. By default, it uses the stack file name (without extension)

 * --plan: for planning changes on a CFN stack (already existing or new stack). It generates a change set and displays the changes.

 * --apply: for applying changes on a CFN stack. A change set is generated then executed.

 * --destroy: for deleting a CFN stack. It displays the list of resources that are going to be removed. `--auto-approve` option is mandatory.

 * --auto-approve: option to be combined with `--delete` option for approving deletion of a stack.

 * --region: Name of the region to deploy the stack. If not set, it uses the region of your AWS profile.

 * --validate: Validate the syntax of the stack file.

 ## Default timeout

 The default timeout for the creation/update/deletion of a stack is `30` minutes.

 The default timeout for the creation of a change set is `10` minutes (used during plan and apply options).
