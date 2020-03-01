## 1.0.4 (March 1, 2020)

IMPROVEMENTS:

* Update logging message when creating/updating a stack

## 1.0.3 (January 30, 2020)

FEATURES:

* Add `--assume-role-arn` option for assuming an IAM role using the supplied credentials (perform an AssumeRole call to AWS STS)

BUG FIXES:

* Fix unhandled error when stack file is empty

## 1.0.2 (January 8, 2020)

BUG FIXES:

* Fix incorrect detection of changes during planning that was causing `No change detected` message in some cases

## 1.0.1 (December 12, 2019)

FEATURES:

* Add support for json parameter file using `--var-file` option

## 1.0.0 (November 7, 2019)

First release

FEATURES:

* Add options for validation, planning, deployment and deletion of a CFN stack
* Add a Dockerfile for building an image containing cfncli tool
* Add a setup.py for building the package
* Add some tests
