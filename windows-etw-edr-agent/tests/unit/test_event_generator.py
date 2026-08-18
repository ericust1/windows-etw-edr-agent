import pytest
from src.modules.event_generator import ETWEventGenerator


@pytest.fixture
def generator():
    return ETWEventGenerator()


class TestProcessCreateEvent:

    def test_has_required_fields(self, generator):
        evt = generator.generate_process_create(
            pid=1234, ppid=500,
            image="C:\\Windows\\System32\\notepad.exe",
            cmdline="notepad.exe test.txt",
            current_dir="C:\\Users\\admin"
        )
        assert evt["process_id"] == 1234
        assert evt["parent_process_id"] == 500
        assert evt["image_name"] == "C:\\Windows\\System32\\notepad.exe"
        assert evt["command_line"] == "notepad.exe test.txt"
        assert evt["event_type"] == "PROCESS_CREATED"
        assert "timestamp" in evt
        assert evt["severity"] == 0

    def test_event_type_is_correct(self, generator):
        evt = generator.generate_process_create(1, 2, "a", "b", "c")
        assert evt["event_type"] == "PROCESS_CREATED"


class TestProcessAccessEvent:

    def test_has_required_fields(self, generator):
        evt = generator.generate_process_access(
            target_pid=668, source_pid=9999, access_mask="0x0010"
        )
        assert evt["target_pid"] == 668
        assert evt["source_pid"] == 9999
        assert evt["access_mask"] == "0x0010"
        assert evt["event_type"] == "PROCESS_ACCESS"


class TestRemoteThreadEvent:

    def test_has_required_fields(self, generator):
        evt = generator.generate_remote_thread(
            source_pid=100, target_pid=200, start_address="0x7FFE12340000"
        )
        assert evt["source_pid"] == 100
        assert evt["target_pid"] == 200
        assert evt["start_address"] == "0x7FFE12340000"
        assert evt["event_type"] == "REMOTE_THREAD_INJECTION"
        assert evt["severity"] == 4


class TestDllLoadEvent:

    def test_has_required_fields(self, generator):
        evt = generator.generate_dll_load(
            pid=1000, dll_name="kernel32.dll", base_address="0x7FFE00100000"
        )
        assert evt["process_id"] == 1000
        assert evt["dll_name"] == "kernel32.dll"
        assert evt["base_address"] == "0x7FFE00100000"
        assert evt["event_type"] == "DLL_LOAD"


class TestLogonEvent:

    def test_has_required_fields(self, generator):
        evt = generator.generate_logon_event(
            sid="S-1-5-21-100-200-300-1000",
            logon_type=3,
            source_ip="10.0.0.5",
            target_computer="WS-01"
        )
        assert evt["sid"] == "S-1-5-21-100-200-300-1000"
        assert evt["logon_type"] == 3
        assert evt["source_ip"] == "10.0.0.5"
        assert evt["target_computer"] == "WS-01"
        assert evt["event_type"] == "LOGON"


class TestAttackScenarios:

    def test_process_hollowing_scenario(self, generator):
        events = generator.generate_attack_scenario('process_hollowing')
        assert len(events) >= 3
        event_types = [e["event_type"] for e in events]
        assert "PROCESS_CREATED" in event_types
        assert "REMOTE_THREAD_INJECTION" in event_types

    def test_credential_dumping_scenario(self, generator):
        events = generator.generate_attack_scenario('credential_dumping')
        assert len(events) >= 2
        event_types = [e["event_type"] for e in events]
        assert "PROCESS_ACCESS" in event_types
        procdump_events = [e for e in events if "procdump" in e.get("command_line", "").lower()]
        assert len(procdump_events) >= 1

    def test_lateral_movement_scenario(self, generator):
        events = generator.generate_attack_scenario('lateral_movement')
        assert len(events) >= 2
        event_types = [e["event_type"] for e in events]
        assert "LOGON" in event_types
        logon_events = [e for e in events if e["event_type"] == "LOGON"]
        assert logon_events[0]["logon_type"] == 3
        assert logon_events[0]["source_ip"] != "127.0.0.1"

    def test_api_hooking_scenario(self, generator):
        events = generator.generate_attack_scenario('api_hooking')
        assert len(events) >= 3
        dll_loads = [e for e in events if e["event_type"] == "DLL_LOAD"]
        assert len(dll_loads) >= 3
        dll_names = [d["dll_name"] for d in dll_loads]
        assert "ntdll.dll" in dll_names

    def test_remote_thread_scenario(self, generator):
        events = generator.generate_attack_scenario('remote_thread_injection')
        assert len(events) >= 2
        injection_events = [e for e in events if e["event_type"] == "REMOTE_THREAD_INJECTION"]
        assert len(injection_events) == 1
        assert injection_events[0]["source_pid"] == 8888

    def test_invalid_scenario_returns_empty(self, generator):
        events = generator.generate_attack_scenario('nonexistent')
        assert len(events) == 0

    def test_scenario_events_have_timestamps(self, generator):
        for scenario in ['process_hollowing', 'credential_dumping', 'lateral_movement',
                         'api_hooking', 'remote_thread_injection']:
            events = generator.generate_attack_scenario(scenario)
            for evt in events:
                assert "timestamp" in evt
