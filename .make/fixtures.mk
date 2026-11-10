# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

.PHONY: prepare-test-fixtures prepare-test-wheels prepare-interpreter-fixture prepare-major-interpreter-fixture prepare-test-inputs
.PHONY: prepare-provenance-identity-fixture

prepare-test-fixtures:
	test ! -L .tool-cache
	test ! -L .tool-cache/native-fixtures
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/strace_6.8-0ubuntu2_amd64.deb
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/bin
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/bin/strace
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/share
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/share/doc
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/share/doc/strace
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/share/doc/strace/copyright
	mkdir -p .tool-cache/native-fixtures/strace-6.8-0ubuntu2
	if test ! -e .tool-cache/native-fixtures/strace-6.8-0ubuntu2/strace_6.8-0ubuntu2_amd64.deb; then curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 584172 --output .tool-cache/native-fixtures/strace-6.8-0ubuntu2/strace_6.8-0ubuntu2_amd64.deb https://archive.ubuntu.com/ubuntu/pool/main/s/strace/strace_6.8-0ubuntu2_amd64.deb; fi
	printf '%s  %s\n' d588810ae26b06fee6678dc81e5b54f6efcde8e718e4589adb4d11d254b9820b .tool-cache/native-fixtures/strace-6.8-0ubuntu2/strace_6.8-0ubuntu2_amd64.deb | sha256sum --check --status
	if test ! -e .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted; then dpkg-deb --extract .tool-cache/native-fixtures/strace-6.8-0ubuntu2/strace_6.8-0ubuntu2_amd64.deb .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted; fi
	printf '%s  %s\n' 28f957c227012de0b18d1bd7fff2d396cb693ea60ed8013be68de071e84b5001 .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/bin/strace | sha256sum --check --status
	printf '%s  %s\n' 40e4ca01654c733c06fabee65168da4c177117b1bd084f3a752bc8a989736e04 .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/share/doc/strace/copyright | sha256sum --check --status

prepare-test-wheels:
	test ! -L .tool-cache
	test ! -L .tool-cache/wheelhouse
	test ! -L .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl
	test ! -L .tool-cache/wheelhouse/coverage-7.16.2-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl
	test ! -L .tool-cache/wheelhouse/pyyaml-6.0.3-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl
	mkdir -p .tool-cache/wheelhouse
	if test ! -e .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl; then curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 129956 --output .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl https://files.pythonhosted.org/packages/63/34/ba1c580383c9eada3711951fef0795c80b829a078d72188184bcab9dd527/packaging-26.3-py3-none-any.whl; fi
	printf '%s  %s\n' d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl | sha256sum --check --status
	if test ! -e .tool-cache/wheelhouse/coverage-7.16.2-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl; then curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 257955 --output .tool-cache/wheelhouse/coverage-7.16.2-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl https://files.pythonhosted.org/packages/1d/56/6785397d07c29c8e70fbb9a07e97d062b43c21ffc5f12385917847f09f63/coverage-7.16.2-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl; fi
	printf '%s  %s\n' 4358b9c8c0125b460407f3017c6cce8156e904b32772c5630d27112f52bdbfe5 .tool-cache/wheelhouse/coverage-7.16.2-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl | sha256sum --check --status
	if test ! -e .tool-cache/wheelhouse/pyyaml-6.0.3-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl; then curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 801626 --output .tool-cache/wheelhouse/pyyaml-6.0.3-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl https://files.pythonhosted.org/packages/74/27/e5b8f34d02d9995b80abcef563ea1f8b56d20134d8f4e5e81733b1feceb2/pyyaml-6.0.3-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl; fi
	printf '%s  %s\n' 0f29edc409a6392443abf94b9cf89ce99889a1dd5376d94316ae5145dfedd5d6 .tool-cache/wheelhouse/pyyaml-6.0.3-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl | sha256sum --check --status

prepare-provenance-identity-fixture:
	test ! -L .tool-cache
	test ! -L .tool-cache/wheelhouse
	test ! -L .tool-cache/wheelhouse/packageurl_python-0.17.5-py3-none-any.whl
	mkdir -p .tool-cache/wheelhouse
	if test ! -e .tool-cache/wheelhouse/packageurl_python-0.17.5-py3-none-any.whl; then curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 30544 --output .tool-cache/wheelhouse/packageurl_python-0.17.5-py3-none-any.whl https://files.pythonhosted.org/packages/be/78/9dbb7d2ef240d20caf6f79c0f66866737c9d0959601fd783ff635d1d019d/packageurl_python-0.17.5-py3-none-any.whl; fi
	printf '%s  %s\n' f0e55452ab37b5c192c443de1458e3f3b4d8ac27f747df6e8c48adeab081d321 .tool-cache/wheelhouse/packageurl_python-0.17.5-py3-none-any.whl | sha256sum --check --status

prepare-interpreter-fixture:
	test ! -L .tool-cache
	test ! -L .tool-cache/native-fixtures
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/cpython-3.13.15+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/extracted
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/extracted/python
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/extracted/python/bin
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/extracted/python/bin/python3.13
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/guard-environment-uv
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/guard-environment-uv/bin
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/guard-environment-uv/bin/python || test "$$(readlink -f .tool-cache/native-fixtures/cpython-3.13.15/guard-environment-uv/bin/python)" = "$$(readlink -f .tool-cache/native-fixtures/cpython-3.13.15/extracted/python/bin/python3.13)"
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/installer-cache
	$(MAKE) --no-print-directory prepare-uv
	$(MAKE) prepare-test-wheels
	mkdir -p .tool-cache/native-fixtures/cpython-3.13.15
	if test ! -e .tool-cache/native-fixtures/cpython-3.13.15/cpython-3.13.15+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz; then curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 35004265 --output .tool-cache/native-fixtures/cpython-3.13.15/cpython-3.13.15+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz https://github.com/astral-sh/python-build-standalone/releases/download/20260929/cpython-3.13.15%2B20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz; fi
	printf '%s  %s\n' c552deaf9ed0e678dee4ccc760d6dcd7cab33f1bd43e8037123b4a4db8508e14 .tool-cache/native-fixtures/cpython-3.13.15/cpython-3.13.15+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz | sha256sum --check --status
	if test ! -e .tool-cache/native-fixtures/cpython-3.13.15/extracted; then $(PYTHON) -I -c 'import pathlib,tarfile; root=pathlib.Path(".tool-cache/native-fixtures/cpython-3.13.15"); target=root/"extracted"; target.mkdir(); archive=tarfile.open(root/"cpython-3.13.15+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"); archive.extractall(target,filter="data"); archive.close()'; fi
	printf '%s  %s\n' bb4d05c1f88e8568985e8704afe1822e82700a54bad9317c05c8eb96d3186701 .tool-cache/native-fixtures/cpython-3.13.15/extracted/python/bin/python3.13 | sha256sum --check --status
	printf '%s  %s\n' d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl | sha256sum --check --status
	printf '%s  %s\n' 4358b9c8c0125b460407f3017c6cce8156e904b32772c5630d27112f52bdbfe5 .tool-cache/wheelhouse/coverage-7.16.2-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl | sha256sum --check --status
	if test ! -e .tool-cache/native-fixtures/cpython-3.13.15/guard-environment-uv; then $(UV) --no-config venv --python .tool-cache/native-fixtures/cpython-3.13.15/extracted/python/bin/python3.13 --no-python-downloads --link-mode hardlink .tool-cache/native-fixtures/cpython-3.13.15/guard-environment-uv && $(UV) --no-config pip install --python .tool-cache/native-fixtures/cpython-3.13.15/guard-environment-uv/bin/python --no-index --no-deps --link-mode hardlink --cache-dir "$(UV_CACHE)" .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl .tool-cache/wheelhouse/coverage-7.16.2-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl; fi
	printf '%s  %s\n' bb4d05c1f88e8568985e8704afe1822e82700a54bad9317c05c8eb96d3186701 .tool-cache/native-fixtures/cpython-3.13.15/guard-environment-uv/bin/python | sha256sum --check --status
	.tool-cache/native-fixtures/cpython-3.13.15/guard-environment-uv/bin/python -I -c 'import hashlib,importlib.metadata,json,platform; expected={"packaging":("26.3","70fdb89fc4d4a9a043bf7372b8972bcc883fddff34ab55e9cf80d73875384763"),"coverage":("7.16.2","a5447449aa5b0b5a8b7c6a800434623a70c316750fcdde7ebd5b0b41fe756f99")}; observed=list(importlib.metadata.distributions()); actual={d.metadata["Name"]:(d.version,hashlib.sha256(d.read_text("METADATA").encode()).hexdigest()) for d in observed}; assert platform.python_version()=="3.13.15" and actual==expected and len(observed)==2; print(json.dumps({"actual_python":platform.python_version(),"qualified_fixture_producers":actual},sort_keys=True))'

prepare-major-interpreter-fixture:
	test ! -L .tool-cache
	test ! -L .tool-cache/native-fixtures
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/cpython-3.14.7+20260901-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/extracted
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/extracted/python
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/extracted/python/bin
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/extracted/python/bin/python3.14
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/guard-environment-uv
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/guard-environment-uv/bin
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/guard-environment-uv/bin/python || test "$$(readlink -f .tool-cache/native-fixtures/cpython-3.14.7/guard-environment-uv/bin/python)" = "$$(readlink -f .tool-cache/native-fixtures/cpython-3.14.7/extracted/python/bin/python3.14)"
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/installer-cache
	test ! -L .tool-cache/wheelhouse
	test ! -L .tool-cache/wheelhouse/coverage-7.16.2-cp314-cp314-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl
	$(MAKE) --no-print-directory prepare-uv
	$(MAKE) prepare-test-wheels
	if test ! -e .tool-cache/wheelhouse/coverage-7.16.2-cp314-cp314-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl; then curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 258727 --output .tool-cache/wheelhouse/coverage-7.16.2-cp314-cp314-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl https://files.pythonhosted.org/packages/a8/d4/a306940c81c6ae759e82fff27d20b7fdc6896e422b821f51313cce212b6c/coverage-7.16.2-cp314-cp314-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl; fi
	mkdir -p .tool-cache/native-fixtures/cpython-3.14.7
	if test ! -e .tool-cache/native-fixtures/cpython-3.14.7/cpython-3.14.7+20260901-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz; then curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 35945651 --output .tool-cache/native-fixtures/cpython-3.14.7/cpython-3.14.7+20260901-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz https://github.com/astral-sh/python-build-standalone/releases/download/20260901/cpython-3.14.7%2B20260901-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz; fi
	printf '%s  %s\n' 3959f92825141e04adf44982d3a83ee57af0877e893b0796e04c1468749d9b04 .tool-cache/native-fixtures/cpython-3.14.7/cpython-3.14.7+20260901-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz | sha256sum --check --status
	if test ! -e .tool-cache/native-fixtures/cpython-3.14.7/extracted; then $(PYTHON) -I -c 'import pathlib,tarfile; root=pathlib.Path(".tool-cache/native-fixtures/cpython-3.14.7"); target=root/"extracted"; target.mkdir(); archive=tarfile.open(root/"cpython-3.14.7+20260901-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"); archive.extractall(target,filter="data"); archive.close()'; fi
	printf '%s  %s\n' 241bf774a81580bb760adf960b48df7e6b23b1de026c9c912d4ca6be1a08241e .tool-cache/native-fixtures/cpython-3.14.7/extracted/python/bin/python3.14 | sha256sum --check --status
	printf '%s  %s\n' d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl | sha256sum --check --status
	printf '%s  %s\n' 35f37886699cb9abd29958247d718628d5bc6f39e623dff66a09e546c42a7e03 .tool-cache/wheelhouse/coverage-7.16.2-cp314-cp314-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl | sha256sum --check --status
	if test ! -e .tool-cache/native-fixtures/cpython-3.14.7/guard-environment-uv; then $(UV) --no-config venv --python .tool-cache/native-fixtures/cpython-3.14.7/extracted/python/bin/python3.14 --no-python-downloads --link-mode hardlink .tool-cache/native-fixtures/cpython-3.14.7/guard-environment-uv && $(UV) --no-config pip install --python .tool-cache/native-fixtures/cpython-3.14.7/guard-environment-uv/bin/python --no-index --no-deps --link-mode hardlink --cache-dir "$(UV_CACHE)" .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl .tool-cache/wheelhouse/coverage-7.16.2-cp314-cp314-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl; fi
	printf '%s  %s\n' 241bf774a81580bb760adf960b48df7e6b23b1de026c9c912d4ca6be1a08241e .tool-cache/native-fixtures/cpython-3.14.7/guard-environment-uv/bin/python | sha256sum --check --status
	.tool-cache/native-fixtures/cpython-3.14.7/guard-environment-uv/bin/python -I -c 'import hashlib,importlib.metadata,json,platform; expected={"packaging":("26.3","70fdb89fc4d4a9a043bf7372b8972bcc883fddff34ab55e9cf80d73875384763"),"coverage":("7.16.2","a5447449aa5b0b5a8b7c6a800434623a70c316750fcdde7ebd5b0b41fe756f99")}; observed=list(importlib.metadata.distributions()); actual={d.metadata["Name"]:(d.version,hashlib.sha256(d.read_text("METADATA").encode()).hexdigest()) for d in observed}; assert platform.python_version()=="3.14.7" and actual==expected and len(observed)==2; print(json.dumps({"actual_python":platform.python_version(),"qualified_fixture_producers":actual},sort_keys=True))'

prepare-test-inputs:
	$(MAKE) prepare-provenance-inputs
	$(MAKE) prepare-provenance-identity-fixture
	$(MAKE) prepare-native
	$(MAKE) prepare-codeql
	$(MAKE) prepare-test-fixtures
	$(MAKE) prepare-interpreter-fixture
	$(MAKE) prepare-major-interpreter-fixture
	$(MAKE) produce-audit
