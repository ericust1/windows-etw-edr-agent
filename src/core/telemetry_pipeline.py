import json
import argparse
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch


class TelemetryPipeline:
    def __init__(self, elasticsearch_host='localhost', es_port=9200):
        self.es = Elasticsearch(
            hosts=[{"host": elasticsearch_host, "port": es_port, "scheme": "http"}],
            request_timeout=30
        )
        self.index_pattern = "etw-telemetry"

    def create_telemetry_index(self):
        mapping = {
            "mappings": {
                "properties": {
                    "process_id": {"type": "integer"},
                    "parent_process_id": {"type": "integer"},
                    "image_name": {
                        "type": "keyword",
                        "fields": {"text": {"type": "text"}}
                    },
                    "command_line": {
                        "type": "text",
                        "fields": {"keyword": {"type": "keyword"}}
                    },
                    "current_directory": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "event_type": {"type": "keyword"},
                    "severity": {"type": "integer"},
                    "details": {"type": "text"},
                    "hostname": {"type": "keyword"},
                    "source_pid": {"type": "integer"},
                    "target_pid": {"type": "integer"},
                    "access_mask": {"type": "keyword"},
                    "dll_name": {"type": "keyword"},
                    "base_address": {"type": "keyword"},
                    "start_address": {"type": "keyword"},
                    "logon_type": {"type": "integer"},
                    "source_ip": {"type": "ip"},
                    "target_computer": {"type": "keyword"},
                    "sid": {"type": "keyword"}
                }
            }
        }
        index_name = self.index_pattern + "-" + datetime.now().strftime("%Y.%m")
        if not self.es.indices.exists(index=index_name):
            self.es.indices.create(index=index_name, body=mapping)
            return True
        return False

    def _get_index_name(self):
        return self.index_pattern + "-" + datetime.now().strftime("%Y.%m")

    def ingest_event(self, event_dict):
        if "timestamp" not in event_dict:
            event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
        index_name = self._get_index_name()
        result = self.es.index(index=index_name, body=event_dict, refresh="wait_for")
        return result

    def bulk_ingest(self, events_list):
        if not events_list:
            return {"errors": False, "items": []}
        index_name = self._get_index_name()
        actions = []
        for evt in events_list:
            if "timestamp" not in evt:
                evt["timestamp"] = datetime.now(timezone.utc).isoformat()
            actions.append({"index": {"_index": index_name}})
            actions.append(evt)
        result = self.es.bulk(body=actions, refresh="wait_for")
        return result

    def query_events(self, query_body, index='etw-telemetry*'):
        result = self.es.search(index=index, body=query_body)
        return result

    def get_recent_events(self, minutes=60):
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=minutes)
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": cutoff.isoformat(),
                        "lte": now.isoformat()
                    }
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": 1000
        }
        result = self.es.search(index="etw-telemetry*", body=query)
        return result


def main():
    parser = argparse.ArgumentParser(description="ETW Telemetry Pipeline")
    parser.add_argument('--host', default='localhost', help='Elasticsearch host')
    parser.add_argument('--port', type=int, default=9200, help='Elasticsearch port')
    parser.add_argument('--create-index', action='store_true', help='Create telemetry index')
    parser.add_argument('--recent', type=int, default=60, help='Get events from last N minutes')
    args = parser.parse_args()

    pipeline = TelemetryPipeline(elasticsearch_host=args.host, es_port=args.port)

    if args.create_index:
        created = pipeline.create_telemetry_index()
        print("Index created" if created else "Index already exists")

    events = pipeline.get_recent_events(minutes=args.recent)
    hits = events.get('hits', {}).get('hits', [])
    print("Found {} events in last {} minutes".format(len(hits), args.recent))
    for hit in hits:
        src = hit.get('_source', {})
        print("  [{}] PID={} Type={}".format(
            src.get('timestamp', 'N/A'),
            src.get('process_id', 'N/A'),
            src.get('event_type', 'N/A')
        ))


if __name__ == '__main__':
    main()
