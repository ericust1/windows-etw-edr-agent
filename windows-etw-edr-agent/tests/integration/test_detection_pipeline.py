import pytest
from unittest.mock import MagicMock, patch
from src.modules.event_generator import ETWEventGenerator
from src.core.telemetry_pipeline import TelemetryPipeline
from src.core.detection_engine import DetectionEngine


SCENARIOS = [
    {
        'name': 'process_hollowing',
        'expected_mitre': 'T1055.012',
        'min_severity': 3
    },
    {
        'name': 'credential_dumping',
        'expected_mitre': 'T1003.001',
        'min_severity': 4
    },
    {
        'name': 'lateral_movement',
        'expected_mitre': 'T1021.002',
        'min_severity': 3
    },
    {
        'name': 'api_hooking',
        'expected_mitre': 'T1055.004',
        'min_severity': 3
    },
    {
        'name': 'remote_thread_injection',
        'expected_mitre': 'T1055.001',
        'min_severity': 3
    }
]


class TestDetectionPipeline:

    @pytest.fixture
    def mock_es(self):
        with patch('src.core.telemetry_pipeline.Elasticsearch') as mock_tp, \
             patch('src.core.detection_engine.Elasticsearch') as mock_de:
            tp_client = MagicMock()
            tp_client.indices.exists.return_value = False
            tp_client.indices.create.return_value = {"acknowledged": True}
            tp_client.bulk.return_value = {"errors": False, "items": [{}]}
            tp_client.index.return_value = {"result": "created", "_id": "1"}
            mock_tp.return_value = tp_client
            mock_de.return_value = MagicMock()
            yield tp_client

    @pytest.fixture
    def pipeline(self, mock_es):
        return TelemetryPipeline()

    @pytest.fixture
    def engine(self):
        with patch('src.core.detection_engine.Elasticsearch'):
            return DetectionEngine()

    def test_full_pipeline_process_hollowing(self, pipeline, engine, mock_es):
        generator = ETWEventGenerator()
        events = generator.generate_attack_scenario('process_hollowing')

        pipeline.bulk_ingest(events)
        assert mock_es.bulk.called

        findings = engine.run_detections(events=events)
        assert len(findings) >= 1

        has_hollowing = any(
            f.mitre_attack_id == 'T1055.012' or 'Hollowing' in f.rule_name
            for f in findings
        )
        assert has_hollowing, "Expected process hollowing detection"

    def test_full_pipeline_credential_dumping(self, pipeline, engine, mock_es):
        generator = ETWEventGenerator()
        events = generator.generate_attack_scenario('credential_dumping')

        pipeline.bulk_ingest(events)
        assert mock_es.bulk.called

        findings = engine.run_detections(events=events)
        assert len(findings) >= 1

        has_cred = any(
            f.mitre_attack_id == 'T1003.001' or 'Credential' in f.rule_name
            for f in findings
        )
        assert has_cred, "Expected credential access detection"

    def test_full_pipeline_lateral_movement(self, pipeline, engine):
        generator = ETWEventGenerator()
        events = generator.generate_attack_scenario('lateral_movement')

        pipeline.bulk_ingest(events)
        findings = engine.run_detections(events=events)
        assert len(findings) >= 1

        has_lateral = any(
            f.mitre_attack_id == 'T1021.002' or 'Lateral' in f.rule_name
            for f in findings
        )
        assert has_lateral, "Expected lateral movement detection"

    def test_full_pipeline_api_hooking(self, pipeline, engine):
        generator = ETWEventGenerator()
        events = generator.generate_attack_scenario('api_hooking')

        pipeline.bulk_ingest(events)
        findings = engine.run_detections(events=events)
        assert len(findings) >= 1

        has_hooking = any(
            'Hooking' in f.rule_name or 'DLL' in f.rule_name
            for f in findings
        )
        assert has_hooking, "Expected API hooking detection"

    def test_full_pipeline_remote_thread(self, pipeline, engine):
        generator = ETWEventGenerator()
        events = generator.generate_attack_scenario('remote_thread_injection')

        pipeline.bulk_ingest(events)
        findings = engine.run_detections(events=events)
        assert len(findings) >= 1

        has_injection = any(
            f.mitre_attack_id == 'T1055.001' or 'Injection' in f.rule_name
            for f in findings
        )
        assert has_injection, "Expected remote thread injection detection"

    def test_findings_have_correct_severity(self, pipeline, engine):
        generator = ETWEventGenerator()
        for scenario in SCENARIOS:
            events = generator.generate_attack_scenario(scenario['name'])
            findings = engine.run_detections(events=events)
            for f in findings:
                assert 1 <= f.severity <= 5, \
                    "Severity {} out of range for {}".format(f.severity, scenario['name'])
                assert f.description, "Finding missing description"
                assert f.rule_name, "Finding missing rule name"
                assert f.timestamp, "Finding missing timestamp"

    def test_combined_scenario_detection(self, pipeline, engine):
        generator = ETWEventGenerator()
        all_events = []
        for scenario in SCENARIOS:
            all_events.extend(generator.generate_attack_scenario(scenario['name']))

        pipeline.bulk_ingest(all_events)
        findings = engine.run_detections(events=all_events)

        rule_names = set(f.rule_name for f in findings)
        assert len(rule_names) >= 3, \
            "Expected at least 3 distinct rule triggers, got {}".format(rule_names)

    def test_pipeline_single_event_ingest(self, pipeline, engine, mock_es):
        generator = ETWEventGenerator()
        event = generator.generate_process_create(
            pid=1, ppid=500, image="test.exe", cmdline="test", current_dir="C:\\\\"
        )
        pipeline.ingest_event(event)
        assert mock_es.index.called
