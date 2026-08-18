# Windows ETW EDR Agent

An endpoint monitoring agent that leverages Event Tracing for Windows (ETW) to detect process injection, API hooking, and credential access techniques in real time.

## Architecture

```
+------------------+     +----------------+     +--------------------+     +----------------+
|                  |     |                |     |                    |     |                |
|  Windows         | --> |  ETW Agent     | --> |  Telemetry         | --> |                |
|  Endpoint        |     |  (C# / ETW)    | HTTP|  Pipeline          |     | Elasticsearch  |
|                  |     |                |     |  (Python)          |     |                |
+------------------+     +----------------+     +--------------------+     +--------+-------+
                                                                       |        |
                                                                       v        v
                                                                +--------------+  +----------------+
                                                                |              |  |                |
                                                                |  Detection   |  |  Kibana        |
                                                                |  Engine      |  |  Dashboards    |
                                                                |  (Python)    |  |                |
                                                                +------+-------+  +----------------+
                                                                       |
                                                                       v
                                                                +--------------+
                                                                |              |
                                                                |  Alerts      |
                                                                |              |
                                                                +--------------+
```

## Features

- ETW subscription to Kernel-Process and Security-Auditing providers
- Process creation and deletion monitoring with parent-child analysis
- Remote thread injection detection (CreateRemoteThread, NtCreateThreadEx)
- Process hollowing detection via image replacement correlation
- API hooking detection through DLL load pattern analysis
- Credential access detection (LSASS memory reading, ProcDump)
- Lateral movement detection via remote logon correlation
- Elasticsearch telemetry storage with Kibana dashboards
- Sysmon configuration generator with detection rationale
- ETW event simulator for lab testing without Windows endpoints

## MITRE ATT&CK Mapping

| Technique | ID | Detection Rule |
|-----------|------|----------------|
| Process Injection | T1055 | Remote Thread Injection |
| Process Hollowing | T1055.012 | Image Replacement + RWX Allocation |
| DLL Injection | T1055.001 | Suspicious DLL Loads |
| API Hooking | T1055.004 | Duplicate System DLL Loads |
| OS Credential Dumping | T1003.001 | LSASS Process Access |
| Command Scripting | T1059.001 | Suspicious Parent-Child Processes |
| Remote Services | T1021.002 | Remote Logon + Process Creation |
| Ingress Tool Transfer | T1105 | File Creation Monitoring |

## Project Structure

```
windows-etw-edr-agent/
  src/
    agent/
      ETWAgent.cs         C# ETW monitoring agent
      ETWAgent.csproj     .NET 8 project file
    core/
      telemetry_pipeline.py   Elasticsearch ingestion
      detection_engine.py     Detection rules engine
    modules/
      event_generator.py       ETW event simulator
      sysmon_config_generator.py  Sysmon XML config generator
  tests/
    unit/
      test_telemetry_pipeline.py
      test_detection_engine.py
      test_event_generator.py
    integration/
      test_detection_pipeline.py
  lab/
    docker-compose.yml     ELK stack + event simulator
    terraform/main.tf      AWS deployment (EC2 + VPC)
  scripts/
    setup.sh               Automated setup
    package_project.py     Distribution packaging
  docs/
    setup-guide.md         Full deployment guide
```

## Quick Start

```
pip install -r requirements.txt
python -m pytest tests/ -v
python -m src.modules.event_generator --scenario credential_dumping --pretty
python -m src.modules.sysmon_config_generator --list-rules
```

## Lab Environment

```
cd lab
docker compose up -d
```

This starts Elasticsearch, Kibana, and an ETW event simulator that generates realistic Windows security events.

## Detection Engine

Run all detection rules against recent telemetry:

```
python -m src.core.detection_engine --host localhost --port 9200 --time-window 300
```

## License

MIT
