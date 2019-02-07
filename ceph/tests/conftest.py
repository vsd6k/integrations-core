# (C) Datadog, Inc. 2018
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)

import os

import pytest

from datadog_checks.dev import docker_run

from .common import HERE, BASIC_CONFIG


@pytest.fixture(scope="session")
def dd_environment():
    with docker_run(
        compose_file=os.path.join(HERE, "compose", "docker-compose.yaml"),
        log_patterns="spawning ceph --cluster ceph -w",
        sleep=2,  # Let's wait just a little bit after ceph got spawned to remove flakyness
    ):
        yield BASIC_CONFIG, "local"
