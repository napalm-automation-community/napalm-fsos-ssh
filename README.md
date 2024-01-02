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
# Devcontainer
A devcontainer is available

# Standard
Install [Poetry](https://python-poetry.org/docs/master/#installing-with-the-official-installer)

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

# Contributing

We welcome and encourage contributions to this project! Please read the [Contributing guide](CONTRIBUTING.md). Also make sure to check the [Code of Conduct](CODE_OF_CONDUCT.md) and adhere to its guidelines

# Security

See [SECURITY.md](SECURITY.md) file for details.

# Licence

The code is under CeCILL license.

You can find all details here: https://cecill.info/licences/Licence_CeCILL_V2.1-en.html

# Credits

Copyright © Ludovic Ortega, 2022

Contributor(s):

-Ortega Ludovic - ludovic.ortega@adminafk.fr
