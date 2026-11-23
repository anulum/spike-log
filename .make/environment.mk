# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

.PHONY: environment check-environment-inputs fetch-environment-inputs prepare-uv prepare-native prepare-codeql produce-audit

environment:
	test ! -L "$(ENVIRONMENT_DIR)"
	test ! -L .tool-cache
	test ! -L .tool-cache/bootstrap-builders.lock
	$(BASE_PYTHON) -B -I -c 'import platform; assert platform.python_version() == "3.13.18"'
	$(MAKE) --no-print-directory prepare-uv
	$(BASE_PYTHON) -B -I -c 'import pathlib; pathlib.Path("$(ENVIRONMENT_DIR)").parent.mkdir(parents=True,exist_ok=True)'
	mkdir -p "$(UV_CACHE)"
	$(BASE_PYTHON) -B -I -c 'import os,sys; assert os.stat(sys.argv[1]).st_dev == os.stat(sys.argv[2]).st_dev, "uv cache and environment must share a filesystem"' "$(UV_CACHE)" "$(dir $(ENVIRONMENT_DIR))"
	if test ! -e "$(ENVIRONMENT_DIR)/pyvenv.cfg"; then $(UV) --no-config venv --python "$(BASE_PYTHON)" --no-python-downloads --link-mode hardlink "$(ENVIRONMENT_DIR)"; fi
	"$(ENVIRONMENT_DIR)/bin/python" -B -I -c 'import platform; assert platform.python_version() == "3.13.18"'
	$(BASE_PYTHON) -B -I -c 'import pathlib,re; text=pathlib.Path("requirements-dev.txt").read_text(); blocks=re.findall(r"(?m)^((?:pip|poetry-core)==[^\n]+\n(?:    [^\n]*\n)*)",text); assert len(blocks)==2; pathlib.Path(".tool-cache/bootstrap-builders.lock").write_text("".join(blocks))'
	$(UV) --no-config pip install --python "$(ENVIRONMENT_DIR)/bin/python" --cache-dir "$(UV_CACHE)" --link-mode hardlink --require-hashes --no-deps --no-index --find-links "$(ENVIRONMENT_INPUTS)" -r .tool-cache/bootstrap-builders.lock
	$(UV) --no-config pip install --python "$(ENVIRONMENT_DIR)/bin/python" --cache-dir "$(UV_CACHE)" --link-mode hardlink --require-hashes --no-deps --no-build-isolation --no-index --find-links "$(ENVIRONMENT_INPUTS)" -r requirements-dev.txt
	$(UV) --no-config pip check --python "$(ENVIRONMENT_DIR)/bin/python"
	"$(ENVIRONMENT_DIR)/bin/python" -B -I -c 'import pathlib,sys; files=list(pathlib.Path(sys.prefix).glob("lib/python3.13/site-packages/*.dist-info/METADATA")); assert files and all(p.stat().st_nlink>1 for p in files), "Package hardlink verification failed"'

fetch-environment-inputs:
	test ! -L .tool-cache
	test ! -L "$(ENVIRONMENT_INPUTS)"
	$(BASE_PYTHON) -B -I -c 'import platform; assert platform.python_version() == "3.13.18"'
	mkdir -p .tool-cache
	$(BASE_PYTHON) -B -I tools/fetch_environment_inputs.py --root . --artifacts "$(ENVIRONMENT_INPUTS)" --json

check-environment-inputs:
	$(BASE_PYTHON) -B -I -c 'import platform; assert platform.python_version() == "3.13.18"'
	$(BASE_PYTHON) -B -I tools/check_environment_inputs.py --root . --artifacts "$(ENVIRONMENT_INPUTS)" --owner-source "$(ENVIRONMENT_OWNER_SOURCE)" --environment "$(ENVIRONMENT_DIR)" --max-input-bytes "$(ENVIRONMENT_INPUT_BYTES)" --json

prepare-uv:
	test ! -L .tool-cache
	test ! -L .tool-cache/bootstrap-uv
	test ! -L "$(UV)"
	$(MAKE) --no-print-directory check-environment-inputs
	mkdir -p .tool-cache/bootstrap-uv
	if test ! -e "$(UV)"; then $(BASE_PYTHON) -B -I -c 'import pathlib,shutil,sys,zipfile; destination=pathlib.Path(sys.argv[2]); archive=zipfile.ZipFile(sys.argv[1]); names=[n for n in archive.namelist() if n.endswith("/scripts/uv")]; assert len(names)==1; source=archive.open(names[0]); target=destination.open("xb"); shutil.copyfileobj(source,target); target.close(); source.close(); archive.close(); destination.chmod(0o755)' "$(ENVIRONMENT_INPUTS)/uv-0.13.7-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl" "$(UV)"; fi
	printf '%s  %s\n' 4b5e59bc557ff2cd70934beb59d0eaa92820702853d49f0066b50aa11a8f0c52 "$(UV)" | sha256sum --check --status


prepare-native:
	test ! -L .tool-cache
	test ! -L .tool-cache/native
	test ! -L .tool-cache/native-artifacts
	test ! -L .tool-cache/native/actionlint
	test ! -L .tool-cache/native/gitleaks
	test ! -L .tool-cache/native/actionlint/actionlint
	test ! -L .tool-cache/native/gitleaks/gitleaks
	test ! -L .tool-cache/native-artifacts/actionlint.tar.gz
	test ! -L .tool-cache/native-artifacts/gitleaks.tar.gz
	mkdir -p .tool-cache/native-artifacts .tool-cache/native/actionlint .tool-cache/native/gitleaks
	test ! -L .tool-cache/native-artifacts
	curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 2353908 --output .tool-cache/native-artifacts/actionlint.tar.gz https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz
	printf '%s  %s\n' 8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8 .tool-cache/native-artifacts/actionlint.tar.gz | sha256sum --check --status
	tar --no-same-owner --no-same-permissions -xzf .tool-cache/native-artifacts/actionlint.tar.gz -C .tool-cache/native/actionlint actionlint
	curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 8230402 --output .tool-cache/native-artifacts/gitleaks.tar.gz https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz
	printf '%s  %s\n' 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb .tool-cache/native-artifacts/gitleaks.tar.gz | sha256sum --check --status
	tar --no-same-owner --no-same-permissions -xzf .tool-cache/native-artifacts/gitleaks.tar.gz -C .tool-cache/native/gitleaks gitleaks

prepare-codeql:
	test ! -L .tool-cache
	test ! -L .tool-cache/native-artifacts
	test ! -L .tool-cache/native-artifacts/codeql-bundle-python-linux64.tar.zst
	mkdir -p .tool-cache/native-artifacts
	test ! -L .tool-cache/native-artifacts
	curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 111165259 --output .tool-cache/native-artifacts/codeql-bundle-python-linux64.tar.zst https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.1/codeql-bundle-python-linux64.tar.zst
	printf '%s  %s\n' ea86393c6c812542ae5a3a7122bcc760873707a50b25cc47d2fd7cfd514b0cb0 .tool-cache/native-artifacts/codeql-bundle-python-linux64.tar.zst | sha256sum --check --status

produce-audit:
	$(PYTHON) tools/check_dependency_alignment.py --root . --produce-audit --json
