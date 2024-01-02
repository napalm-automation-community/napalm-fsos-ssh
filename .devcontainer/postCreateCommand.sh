#!/bin/bash

# Setup poetry
poetry install --with=dev
poetry shell
pre-commit install
