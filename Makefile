# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

PYTHON := .venv/bin/python
BASE_PYTHON ?= python
ENVIRONMENT_DIR ?= .venv
ENVIRONMENT_INPUTS ?= .tool-cache/environment-inputs
ENVIRONMENT_OWNER_SOURCE ?=
ENVIRONMENT_INPUT_BYTES ?= 134217728
UV := .tool-cache/bootstrap-uv/uv
UV_CACHE_DIR ?=
UV_CACHE = $(if $(UV_CACHE_DIR),$(UV_CACHE_DIR),$$($(UV) cache dir))
TEST_WORKERS ?= 0
TEST_SELECTION ?= tests
TEST_BASETEMP ?= .tool-cache/tests
LOCAL_SOURCE_ARTIFACTS ?= .
LOCAL_SOURCE_INPUTS ?= .tool-cache/environment-inputs
LOCAL_SOURCE_OWNER ?= $(ENVIRONMENT_OWNER_SOURCE)

export SPIKE_LOG_TEST_ARTIFACTS := $(abspath $(LOCAL_SOURCE_ARTIFACTS))
export SPIKE_LOG_TEST_LOCAL_INPUTS := $(abspath $(LOCAL_SOURCE_INPUTS))
export SPIKE_LOG_TEST_OWNER_SOURCE := $(abspath $(LOCAL_SOURCE_OWNER))

include .make/quality.mk
include .make/environment.mk
include .make/fixtures.mk
