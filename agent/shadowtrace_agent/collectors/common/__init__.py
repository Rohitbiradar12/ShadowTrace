from shadowtrace_agent.collectors.common.browser import BrowserCollector
from shadowtrace_agent.collectors.common.file import FileCollector
from shadowtrace_agent.collectors.common.network import NetworkCollector
from shadowtrace_agent.collectors.common.process import ProcessCollector

COLLECTORS = [ProcessCollector, FileCollector, NetworkCollector, BrowserCollector]
