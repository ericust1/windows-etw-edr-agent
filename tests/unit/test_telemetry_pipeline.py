import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from src.core.telemetry_pipeline import TelemetryPipeline


@pytest.fixture
def mock_es_client():
    with patch('src.core.telemetry_pipeline.Elasticsearch') as mock_es_cls:
        mock_client = MagicMock()
        mock_es_cls.return_value = mock_client
        yield mock_client


@pytest.fixture
def pipeline(mock_es_client):
    return TelemetryPipeline(elasticsearch_host='localhost', es_port=9200)


class TestTelemetryPipeline:

    def test_init_creates_es_client(self):
        with patch('src.core.telemetry_pipeline.Elasticsearch') as mock_es_cls:
            mock_es_cls.return_value = MagicMock()
            TelemetryPipeline(elasticsearch_host='10.0.0.1', es_port=9300)
            mock_es_cls.assert_called()
            call_kwargs = mock_es_cls.call_args[1]
            assert call_kwargs['hosts'][0]['host'] == '10.0.0.1'
            assert call_kwargs['hosts'][0]['port'] == 9300

    def test_ingest_event_calls_index(self, pipeline, mock_es_client):
        event = {
            "process_id": 1234,
            "event_type": "PROCESS_CREATED",
            "image_name": "test.exe"
        }
        mock_es_client.index.return_value = {"result": "created", "_id": "abc123"}
        result = pipeline.ingest_event(event)
        mock_es_client.index.assert_called_once()
        call_args = mock_es_client.index.call_args
        assert call_args[1]['body']['process_id'] == 1234
        assert call_args[1]['body']['event_type'] == "PROCESS_CREATED"
        assert 'timestamp' in call_args[1]['body']

    def test_bulk_ingest_calls_bulk(self, pipeline, mock_es_client):
        events = [
            {"process_id": 1, "event_type": "PROCESS_CREATED"},
            {"process_id": 2, "event_type": "PROCESS_CREATED"},
            {"process_id": 3, "event_type": "DLL_LOAD"}
        ]
        mock_es_client.bulk.return_value = {"errors": False, "items": [{}, {}, {}]}
        result = pipeline.bulk_ingest(events)
        mock_es_client.bulk.assert_called_once()
        call_body = mock_es_client.bulk.call_args[1]['body']
        action_count = sum(1 for item in call_body if isinstance(item, dict) and 'index' in item)
        assert action_count == 3

    def test_bulk_ingest_empty_list(self, pipeline, mock_es_client):
        result = pipeline.bulk_ingest([])
        assert result == {"errors": False, "items": []}
        mock_es_client.bulk.assert_not_called()

    def test_query_events_calls_search(self, pipeline, mock_es_client):
        query = {"query": {"match_all": {}}}
        mock_es_client.search.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"process_id": 1, "event_type": "PROCESS_CREATED"}}
                ]
            }
        }
        result = pipeline.query_events(query)
        mock_es_client.search.assert_called_once()
        assert len(result['hits']['hits']) == 1

    def test_get_recent_events(self, pipeline, mock_es_client):
        mock_es_client.search.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"process_id": 1}},
                    {"_source": {"process_id": 2}}
                ]
            }
        }
        result = pipeline.get_recent_events(minutes=30)
        mock_es_client.search.assert_called_once()
        call_body = mock_es_client.search.call_args[1]['body']
        assert 'range' in call_body['query']
        assert 'timestamp' in call_body['query']['range']
        assert call_body['size'] == 1000

    def test_create_telemetry_index_new(self, pipeline, mock_es_client):
        mock_es_client.indices.exists.return_value = False
        mock_es_client.indices.create.return_value = {"acknowledged": True}
        result = pipeline.create_telemetry_index()
        assert result is True
        mock_es_client.indices.create.assert_called_once()
        call_body = mock_es_client.indices.create.call_args[1]['body']
        assert 'mappings' in call_body
        assert 'process_id' in call_body['mappings']['properties']
        assert 'event_type' in call_body['mappings']['properties']
        assert 'severity' in call_body['mappings']['properties']

    def test_create_telemetry_index_exists(self, pipeline, mock_es_client):
        mock_es_client.indices.exists.return_value = True
        result = pipeline.create_telemetry_index()
        assert result is False
        mock_es_client.indices.create.assert_not_called()

    def test_ingest_event_adds_timestamp(self, pipeline, mock_es_client):
        event = {"process_id": 42, "event_type": "DLL_LOAD"}
        mock_es_client.index.return_value = {"result": "created"}
        pipeline.ingest_event(event)
        call_args = mock_es_client.index.call_args
        assert 'timestamp' in call_args[1]['body']
