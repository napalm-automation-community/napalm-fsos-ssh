Napalm driver for FSOS using SSH

[![PyPI](https://img.shields.io/pypi/v/napalm-fsos-ssh.svg)](https://pypi.python.org/pypi/napalm-fsos-ssh)
[![PyPI versions](https://img.shields.io/pypi/pyversions/napalm-fsos-ssh.svg)](https://pypi.python.org/pypi/napalm-fsos-ssh)
[![Python test](https://github.com/napalm-automation-community/napalm-fsos-ssh/actions/workflows/test.yml/badge.svg)](https://github.com/napalm-automation-community/napalm-fsos-ssh/actions/workflows/test.yml)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)

# Warning
This driver has been tested only on S3900 24T4S with version 1.7.3

# Install
```
pip install napalm-fsos-ssh
```

# Dev
Install [Poetry](https://python-poetry.org/docs/master/#installing-with-the-official-installer) with version >= 1.2.0a1

Install and setup dependencies
```
poetry install
poetry shell
pre-commit install
```

### Run unit test
```
pytest
```

### Run pre-commit
```
pre-commit run --all-files
```

# Switch configuration

In order to use the driver you need to enable ssh:
```
ip ssh server enable
```

You also need to configure a username and password with ro permission to authenticate with ssh
You can change privilege level regarding driver capability you needs
```
username <your_username> password 0 <your_password>
username <your_username> privilege 15
```

# Licence

The code is under CeCILL license.

You can find all details here: https://cecill.info/licences/Licence_CeCILL_V2.1-en.html

# Credits

Copyright © Ludovic Ortega, 2022

Contributor(s):

-Ortega Ludovic - ludovic.ortega@adminafk.fr
