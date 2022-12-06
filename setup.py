import re

from glob import glob
from setuptools import setup

def readme():
    with open('README.md') as f:
        return f.read()

_pkg_name = 'sd_jwt'

with open(f'{_pkg_name}/__init__.py', 'r') as fd:
    VERSION = re.search(
        r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
        fd.read(), re.MULTILINE
    ).group(1)

setup(
    name=_pkg_name,
    version=VERSION,
    description="Selective Disclosure for JWTs (SD-JWT)",
    long_description_content_type='text/markdown',
    classifiers=['Development Status :: 1 - Planning Copy',
                 'License :: OSI Approved :: MIT License',
                 'Programming Language :: Python :: 3'],
    url='https://github.com/oauthstuff/draft-selective-disclosure-jwt',
    author='IETF',
    license='License :: OSI Approved :: MIT License',
    scripts=[f'{_pkg_name}/bin/{_pkg_name}'],
    packages=[f"{_pkg_name}"],
    package_dir={f"{_pkg_name}": f"{_pkg_name}"},
    package_data={f"{_pkg_name}": [
            i.replace(f'{_pkg_name}/', '')
            for i in glob(f'{_pkg_name}/**', recursive=True)
        ]
    },
    install_requires=[
        "jwcrypto>=1.3.1",
        "pyyaml>=5.4",
    ],
)
