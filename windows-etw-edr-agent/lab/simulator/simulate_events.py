import os
import sys
import time
import random
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from elasticsearch import Elasticsearch
from src.modules.event_generator import ETWEventGenerator


def wait_for_elasticsearch(host, port, timeout=120):
    es = Elasticsearch(hosts=[{"host": host, "port": port, "scheme": "http"}], request_timeout=5)
    start = time.time()
    while time.time() - start < timeout:
        try:
            if es.ping():
                print("Elasticsearch is ready")
                return es
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError("Elasticsearch not available after {} seconds".format(timeout))


def create_index(es):
    index_name = "etw-telemetry-{}".format(datetime.now().strftime("%Y.%m"))
    mapping = {
        "mappings": {
            "properties": {
                "process_id": {"type": "integer"},
                "parent_process_id": {"type": "integer"},
                "image_name": {"type": "keyword"},
                "command_line": {"type": "text"},
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
    if not es.indices.exists(index=index_name):
        es.indices.create(index=index_name, body=mapping)
        print("Created index: {}".format(index_name))
    return index_name


def generate_benign_events(generator, count=50):
    events = []
    benign_processes = [
        ("explorer.exe", "explorer.exe"),
        ("notepad.exe", "notepad.exe readme.txt"),
        ("chrome.exe", "chrome.exe --start-maximized"),
        ("svchost.exe", "svchost.exe -k netsvcs"),
        ("SearchHost.exe", "SearchHost.exe"),
        ("RuntimeBroker.exe", "RuntimeBroker.exe -ServerName:"),
    ]
    for i in range(count):
        image, cmdline = random.choice(benign_processes)
        events.append(generator.generate_process_create(
            pid=10000 + i,
            ppid=random.randint(500, 2000),
            image="C:\\Windows\\System32\\" + image,
            cmdline=cmdline,
            current_dir="C:\\Windows\\System32"
        ))
    return events


def main():
    es_host = os.environ.get("ELASTICSEARCH_HOST", "localhost")
    es_port = int(os.environ.get("ELASTICSEARCH_PORT", "9200"))

    print("ETW Event Simulator starting...")
    es = wait_for_elasticsearch(es_host, es_port)
    index_name = create_index(es)

    generator = ETWEventGenerator()
    scenarios = [
        "process_hollowing",
        "credential_dumping",
        "lateral_movement",
        "api_hooking",
        "remote_thread_injection"
    ]

    cycle = 0
    while True:
        cycle += 1
        print("Cycle {}: ingesting events...".format(cycle))

        all_events = []
        all_events.extend(generate_benign_events(generator, count=20))

        attack_scenario = random.choice(scenarios)
        attack_events = generator.generate_attack_scenario(attack_scenario)
        all_events.extend(attack_events)
        print("  Generated {} events (attack: {})".format(len(all_events), attack_scenario))

        actions = []
        for evt in all_events:
            evt["hostname"] = "SIMULATED-WINDOWS-01"
            evt["agent_version"] = "1.0.0"
            if "timestamp" not in evt:
                evt["timestamp"] = datetime.now(timezone.utc).isoformat()
            actions.append({"index": {"_index": index_name}})
            actions.append(evt)

        result = es.bulk(body=actions, refresh="wait_for")
        errors = result.get("errors", False)
        print("  Bulk ingest: errors={}".format(errors))

        time.sleep(30)


if __name__ == "__main__":
    main()
