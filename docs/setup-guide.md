# ETW EDR Agent Setup Guide

## Prerequisites

- Windows 10/11 or Windows Server 2019+
- Administrator privileges
- .NET 8 SDK
- Python 3.9+
- Sysmon v15+

## 1. Install .NET 8 SDK

Download and install the .NET 8 SDK from https://dotnet.microsoft.com/download/dotnet/8.0

Verify the installation:

```
dotnet --version
```

## 2. Install Python Dependencies

```
cd windows-etw-edr-agent
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## 3. Install Sysmon

1. Download Sysmon from the Sysinternals Live site or Microsoft.
2. Copy `sysmon64.exe` to `C:\Program Files\ETW-EDR-Agent\`.
3. Generate a configuration using the included generator:

```
python -m src.modules.sysmon_config_generator --rules 1 3 7 8 10 11 --output sysmonconfig.xml
```

4. Install Sysmon with the configuration:

```
sysmon64.exe -i sysmonconfig.xml
```

5. Verify Sysmon is running:

```
sc query Sysmon64
```

## 4. Configure ETW Providers

The ETW agent subscribes to these providers automatically:

- `Microsoft-Windows-Kernel-Process` (GUID: 22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716)
- `Microsoft-Windows-Security-Auditing` (GUID: 54849625-5478-4994-A5BA-3E3B0328C30D)

Enable the providers manually if needed:

```
logman create trace ETW-Kernel-Process -p {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} -o C:\etw-logs\kernel.etl
```

## 5. Deploy the Agent

Build the C# agent:

```
cd src/agent
dotnet publish -c Release -o C:\Program Files\ETW-EDR-Agent\
```

Start the agent:

```
C:\"Program Files\ETW-EDR-Agent\ETWAgent.exe" http://your-elk-server:8080/api/ingest
```

## 6. Configure Ingestion Pipeline

Start the ELK stack (see lab/docker-compose.yml):

```
cd lab
docker compose up -d
```

Create the telemetry index:

```
python -m src.core.telemetry_pipeline --host localhost --port 9200 --create-index
```

## 7. Run the Detection Engine

```
python -m src.core.detection_engine --host localhost --port 9200 --time-window 300
```

## 8. Verify Telemetry

Generate test events:

```
python -m src.modules.event_generator --scenario process_hollowing --pretty
```

Check recent events:

```
python -m src.core.telemetry_pipeline --host localhost --recent 60
```

## 9. Lab Environment

For testing without a Windows endpoint, use the Docker-based lab:

```
cd lab
docker compose up -d
python lab/simulate_events.py
```

## Troubleshooting

- If ETW provider GUIDs are not registered, run `logman query providers` to verify.
- If Elasticsearch is not reachable, check firewall rules and ensure port 9200 is open.
- If Sysmon events are not appearing, verify the Sysmon service is running and the configuration was applied.
