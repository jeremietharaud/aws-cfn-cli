import codecs
import os.path
import re
from setuptools import setup, find_packages


here = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    return codecs.open(os.path.join(here, *parts), 'r').read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


def find_required():
    with open('requirements.txt') as f:
        required = f.read().splitlines()
    return required[1:]


setup(
    name="cfncli",
    version=find_version("cfncli", "__init__.py"),
    author="Jeremie Tharaud",
    author_email="jeremie.tharaud@gmail.com",
    description="Yet Another Friendly AWS CloudFormation CLI",
    long_description=read('README.md'),
    long_description_content_type="text/markdown",
    url="https://github.com/jeremietharaud/aws-cfn-cli",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: Apache License",
        "Operating System :: OS Independent",
    ],
    entry_points='''
        [console_scripts]
        cfncli=cfncli.cfncli:main
    ''',
    license='Apache',
    install_requires=find_required(),
    include_package_data=True,
    zip_safe=False
)
