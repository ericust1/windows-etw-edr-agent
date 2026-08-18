import pytest
from unittest.mock import MagicMock, patch
from src.core.detection_engine import DetectionEngine, DetectionFinding
from src.modules.event_generator import ETWEventGenerator


@pytest.fixture
def engine():
    with patch('src.core.detection_engine.Elasticsearch'):
        return DetectionEngine(es_host='localhost', es_port=9200)


@pytest.fixture
def generator():
    return ETWEventGenerator()


class TestProcessHollowing:

    def test_detects_image_replacement(self, engine):
        events = [
            {"process_id": 100, "event_type": "PROCESS_CREATED",
             "image_name": "C:\\Windows\\System32\\svchost.exe"},
            {"process_id": 100, "event_type": "PROCESS_CREATED",
             "image_name": "C:\\Temp\\malware.exe"}
        ]
        findings = engine.detect_process_hollowing(events)
        assert len(findings) >= 1
        assert any(f.rule_name == "Process Hollowing" for f in findings)

    def test_no_false_positive_normal_processes(self, engine):
        events = [
            {"process_id": 100, "event_type": "PROCESS_CREATED",
             "image_name": "C:\\Windows\\System32\\svchost.exe"},
            {"process_id": 200, "event_type": "PROCESS_CREATED",
             "image_name": "C:\\Windows\\System32\\notepad.exe"}
        ]
        findings = engine.detect_process_hollowing(events)
        assert len(findings) == 0

    def test_hollowing_with_injection_details(self, engine):
        events = [
            {"event_type": "REMOTE_THREAD_INJECTION",
             "details": "Process hollowing pattern: RWX allocation detected"}
        ]
        findings = engine.detect_process_hollowing(events)
        assert len(findings) >= 1
        assert findings[0].mitre_attack_id == "T1055.012"


class TestRemoteThreadInjection:

    def test_detects_basic_injection(self, engine, generator):
        events = generator.generate_attack_scenario('remote_thread_injection')
        findings = engine.detect_remote_thread_injection(events)
        assert len(findings) >= 1
        assert any(f.mitre_attack_id == "T1055.001" for f in findings)

    def test_system_process_injection_high_severity(self, engine):
        events = [
            {"event_type": "REMOTE_THREAD_INJECTION",
             "source_pid": 500, "target_pid": 1234,
             "source_image": "svchost.exe",
             "image_name": "notepad.exe"}
        ]
        findings = engine.detect_remote_thread_injection(events)
        assert len(findings) >= 1
        assert findings[0].severity == 5

    def test_no_injection_with_no_events(self, engine):
        findings = engine.detect_remote_thread_injection([])
        assert len(findings) == 0


class TestAPIHooking:

    def test_detects_duplicate_dll_load(self, engine, generator):
        events = generator.generate_attack_scenario('api_hooking')
        findings = engine.detect_api_hooking(events)
        hooking_findings = [f for f in findings if f.rule_name == "API Hooking Detected"]
        assert len(hooking_findings) >= 1

    def test_detects_suspicious_dll_location(self, engine):
        events = [
            {"process_id": 100, "event_type": "DLL_LOAD",
             "dll_name": "C:\\Users\\admin\\AppData\\Local\\Temp\\hook.dll",
             "base_address": "0x7FFE12340000"}
        ]
        findings = engine.detect_api_hooking(events)
        assert len(findings) >= 1
        assert any("Suspicious DLL Load" in f.rule_name for f in findings)

    def test_normal_dll_loads_no_findings(self, engine):
        events = [
            {"process_id": 100, "event_type": "DLL_LOAD",
             "dll_name": "kernel32.dll", "base_address": "0x7FFE00100000"},
            {"process_id": 100, "event_type": "DLL_LOAD",
             "dll_name": "user32.dll", "base_address": "0x7FFE00200000"}
        ]
        findings = engine.detect_api_hooking(events)
        assert len(findings) == 0


class TestCredentialAccess:

    def test_detects_lsass_access(self, engine):
        events = [
            {"event_type": "PROCESS_ACCESS",
             "target_pid": 668, "source_pid": 9999,
             "access_mask": "0x0010|0x0008|0x00100000",
             "target_image": "lsass.exe"}
        ]
        findings = engine.detect_credential_access(events)
        assert len(findings) >= 1
        assert findings[0].mitre_attack_id == "T1003.001"

    def test_detects_procdump(self, engine):
        events = [
            {"event_type": "PROCESS_CREATED",
             "image_name": "C:\\tools\\procdump.exe",
             "command_line": "procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp",
             "process_id": 5000, "parent_process_id": 1000}
        ]
        findings = engine.detect_credential_access(events)
        assert len(findings) >= 1
        assert any("ProcDump" in f.rule_name for f in findings)

    def test_normal_process_access_no_findings(self, engine):
        events = [
            {"event_type": "PROCESS_ACCESS",
             "target_pid": 100, "source_pid": 200,
             "access_mask": "0x0001",
             "target_image": "notepad.exe"}
        ]
        findings = engine.detect_credential_access(events)
        assert len(findings) == 0


class TestSuspiciousChildProcesses:

    def test_svchost_spawning_cmd(self, engine):
        events = [
            {"event_type": "PROCESS_CREATED", "process_id": 500,
             "parent_process_id": 600, "image_name": "svchost.exe"},
            {"event_type": "PROCESS_CREATED", "process_id": 501,
             "parent_process_id": 500, "image_name": "cmd.exe"}
        ]
        findings = engine.detect_suspicious_child_processes(events)
        assert len(findings) >= 1
        assert any("Suspicious Parent-Child" in f.rule_name for f in findings)

    def test_lsass_spawning_powershell(self, engine):
        events = [
            {"event_type": "PROCESS_CREATED", "process_id": 668,
             "parent_process_id": 4, "image_name": "lsass.exe"},
            {"event_type": "PROCESS_CREATED", "process_id": 669,
             "parent_process_id": 668, "image_name": "powershell.exe"}
        ]
        findings = engine.detect_suspicious_child_processes(events)
        assert len(findings) >= 1

    def test_explorer_spawning_notepad_no_findings(self, engine):
        events = [
            {"event_type": "PROCESS_CREATED", "process_id": 1000,
             "parent_process_id": 500, "image_name": "explorer.exe"},
            {"event_type": "PROCESS_CREATED", "process_id": 1001,
             "parent_process_id": 1000, "image_name": "notepad.exe"}
        ]
        findings = engine.detect_suspicious_child_processes(events)
        assert len(findings) == 0


class TestDetectionFinding:

    def test_to_dict_has_required_fields(self):
        finding = DetectionFinding(
            rule_name="Test Rule",
            description="Test description",
            severity=3,
            mitre_attack_id="T1055"
        )
        d = finding.to_dict()
        assert d["rule_name"] == "Test Rule"
        assert d["severity"] == 3
        assert d["mitre_attack_id"] == "T1055"
        assert "timestamp" in d


class TestLateralMovement:

    def test_detects_lateral_movement(self, engine, generator):
        events = generator.generate_attack_scenario('lateral_movement')
        findings = engine.detect_lateral_movement(events)
        assert len(findings) >= 1
        assert any(f.mitre_attack_id == "T1021.002" for f in findings)

    def test_local_logon_no_lateral_movement(self, engine):
        events = [
            {"event_type": "LOGON", "logon_type": 2,
             "source_ip": "127.0.0.1", "target_computer": "LOCAL-PC"},
            {"event_type": "PROCESS_CREATED", "image_name": "cmd.exe"}
        ]
        findings = engine.detect_lateral_movement(events)
        assert len(findings) == 0


class TestRunDetections:

    def test_runs_all_detection_rules(self, engine):
        events = []
        gen = ETWEventGenerator()
        events.extend(gen.generate_attack_scenario('credential_dumping'))
        events.extend(gen.generate_attack_scenario('lateral_movement'))
        events.extend(gen.generate_attack_scenario('api_hooking'))

        findings = engine.run_detections(events=events)
        rule_names = set(f.rule_name for f in findings)
        assert len(findings) > 0

    def test_empty_events_no_findings(self, engine):
        findings = engine.run_detections(events=[])
        assert len(findings) == 0

    def test_findings_sorted_by_severity(self, engine):
        events = [
            {"event_type": "REMOTE_THREAD_INJECTION",
             "source_pid": 500, "target_pid": 1234,
             "source_image": "svchost.exe", "image_name": "cmd.exe"},
            {"event_type": "PROCESS_CREATED", "process_id": 500,
             "parent_process_id": 4, "image_name": "svchost.exe"},
            {"event_type": "PROCESS_CREATED", "process_id": 501,
             "parent_process_id": 500, "image_name": "cmd.exe"}
        ]
        findings = engine.run_detections(events=events)
        if len(findings) >= 2:
            for i in range(len(findings) - 1):
                assert findings[i].severity >= findings[i + 1].severity
