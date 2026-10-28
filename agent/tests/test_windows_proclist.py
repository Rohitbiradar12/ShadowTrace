import os
import sys
import time

import psutil
import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only API")


def test_snapshot_matches_psutil_for_own_process():
    from shadowtrace_agent.collectors.windows.proclist import list_processes

    rows = {pid: (ppid, name, ctime) for pid, ppid, name, ctime in list_processes()}

    ppid, name, ctime = rows[os.getpid()]
    me = psutil.Process()
    assert ppid == me.ppid()
    assert name.lower() == me.name().lower()
    assert abs(ctime - me.create_time()) < 0.01


def test_snapshot_is_fast():
    from shadowtrace_agent.collectors.windows.proclist import list_processes

    start = time.perf_counter()
    rows = list_processes()
    assert time.perf_counter() - start < 0.5
    assert len(rows) > 10
