from agentdojo.task_suite import register_suite

import benchmark.attacks.bash_injection_attack  # noqa: F401  # registers BashInjectionAttack, BashInjectionAttackEnhanced

from benchmark.suites.command_execution_injection import injection_tasks as command_execution_injection_injection_tasks  # noqa: F401
from benchmark.suites.command_execution_injection import task_suite as command_execution_injection_task_suite
from benchmark.suites.command_execution_injection import user_tasks as command_execution_injection_user_tasks  # noqa: F401
from benchmark.suites.credential_exfiltration import injection_tasks as credential_exfiltration_injection_tasks  # noqa: F401
from benchmark.suites.credential_exfiltration import task_suite as credential_exfiltration_task_suite
from benchmark.suites.credential_exfiltration import user_tasks as credential_exfiltration_user_tasks  # noqa: F401
from benchmark.suites.direct_task_injection import injection_tasks as direct_task_injection_injection_tasks  # noqa: F401
from benchmark.suites.direct_task_injection import task_suite as direct_task_injection_task_suite
from benchmark.suites.direct_task_injection import user_tasks as direct_task_injection_user_tasks  # noqa: F401
from benchmark.suites.monitoring_blind import injection_tasks as monitoring_blind_injection_tasks  # noqa: F401
from benchmark.suites.monitoring_blind import task_suite as monitoring_blind_task_suite
from benchmark.suites.monitoring_blind import user_tasks as monitoring_blind_user_tasks  # noqa: F401
from benchmark.suites.file_content_injection import injection_tasks as file_content_injection_injection_tasks  # noqa: F401
from benchmark.suites.file_content_injection import task_suite as file_content_injection_task_suite
from benchmark.suites.file_content_injection import user_tasks as file_content_injection_user_tasks  # noqa: F401
from benchmark.suites.search_triggered_exfiltration import injection_tasks as search_triggered_exfiltration_injection_tasks  # noqa: F401
from benchmark.suites.search_triggered_exfiltration import task_suite as search_triggered_exfiltration_task_suite
from benchmark.suites.search_triggered_exfiltration import user_tasks as search_triggered_exfiltration_user_tasks  # noqa: F401
from benchmark.suites.web_content_injection import injection_tasks as web_content_injection_injection_tasks  # noqa: F401
from benchmark.suites.web_content_injection import task_suite as web_content_injection_task_suite
from benchmark.suites.web_content_injection import user_tasks as web_content_injection_user_tasks  # noqa: F401

benchmark_version = "argus_benchmark"
register_suite(web_content_injection_task_suite, benchmark_version)
register_suite(file_content_injection_task_suite, benchmark_version)
register_suite(credential_exfiltration_task_suite, benchmark_version)
register_suite(search_triggered_exfiltration_task_suite, benchmark_version)
register_suite(command_execution_injection_task_suite, benchmark_version)
register_suite(direct_task_injection_task_suite, benchmark_version)
register_suite(monitoring_blind_task_suite, benchmark_version)
