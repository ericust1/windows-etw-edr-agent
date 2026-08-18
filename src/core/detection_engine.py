import argparse
from datetime import datetime, timezone
from elasticsearch import Elasticsearch


class DetectionFinding:
    def __init__(self, rule_name, description, severity, event_ids=None, mitre_attack_id=None):
        self.rule_name = rule_name
        self.description = description
        self.severity = severity
        self.event_ids = event_ids or []
        self.mitre_attack_id = mitre_attack_id
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return {
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity,
            "event_ids": self.event_ids,
            "mitre_attack_id": self.mitre_attack_id,
            "timestamp": self.timestamp
        }


class DetectionEngine:
    SUSPICIOUS_PARENT_CHILD = {
        "svchost.exe": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"],
        "lsass.exe": ["cmd.exe", "powershell.exe"],
        "csrss.exe": ["cmd.exe", "powershell.exe"],
        "smss.exe": ["cmd.exe", "powershell.exe"],
        "services.exe": ["cmd.exe", "powershell.exe", "rundll32.exe"],
        "winlogon.exe": ["cmd.exe", "powershell.exe"],
        "dwm.exe": ["cmd.exe", "powershell.exe"]
    }

    HOOKING_DLL_PATTERNS = [
        "user32.dll", "ntdll.dll", "kernel32.dll"
    ]

    def __init__(self, es_host='localhost', es_port=9200):
        self.es = Elasticsearch(
            hosts=[{"host": es_host, "port": es_port, "scheme": "http"}],
            request_timeout=30
        )

    def detect_process_hollowing(self, events):
        findings = []
        process_map = {}
        image_changes = []

        for evt in events:
            evt_type = evt.get("event_type", "")
            if evt_type == "PROCESS_CREATED":
                pid = evt.get("process_id")
                image = evt.get("image_name", "")
                if pid:
                    if pid in process_map and process_map[pid] != image:
                        image_changes.append({
                            "pid": pid,
                            "original_image": process_map[pid],
                            "new_image": image,
                            "event": evt
                        })
                    else:
                        process_map[pid] = image

        for change in image_changes:
            finding = DetectionFinding(
                rule_name="Process Hollowing",
                description="Image replacement: PID {} changed from {} to {}".format(
                    change["pid"], change["original_image"], change["new_image"]
                ),
                severity=4,
                mitre_attack_id="T1055.012"
            )
            findings.append(finding)

        for evt in events:
            if evt.get("event_type") == "REMOTE_THREAD_INJECTION":
                details = evt.get("details", "")
                if "hollowing" in details.lower() or "RWX" in details:
                    finding = DetectionFinding(
                        rule_name="Process Hollowing (Injection Pattern)",
                        description="Remote thread injection with hollowing indicators: {}".format(details),
                        severity=5,
                        mitre_attack_id="T1055.012"
                    )
                    findings.append(finding)

        return findings

    def detect_remote_thread_injection(self, events):
        findings = []
        legitimate_injectors = {"svchost.exe", "csrss.exe", "smss.exe"}
        allowed_targets = {"explorer.exe"}

        for evt in events:
            if evt.get("event_type") != "REMOTE_THREAD_INJECTION":
                continue

            source_pid = evt.get("source_pid") or evt.get("parent_process_id")
            target_pid = evt.get("target_pid") or evt.get("process_id")

            if not source_pid or not target_pid:
                findings.append(DetectionFinding(
                    rule_name="Remote Thread Injection",
                    description="Remote thread detected with incomplete metadata",
                    severity=3,
                    mitre_attack_id="T1055.001"
                ))
                continue

            source_image = evt.get("source_image", "").lower()
            target_image = evt.get("image_name", "").lower()
            source_base = source_image.split("\\")[-1] if "\\" in source_image else source_image

            if source_base in legitimate_injectors:
                if target_image.lower().split("\\")[-1] not in allowed_targets:
                    findings.append(DetectionFinding(
                        rule_name="Remote Thread Injection (System Process)",
                        description="System process {} (PID {}) injected into {} (PID {})".format(
                            source_base, source_pid, target_image, target_pid
                        ),
                        severity=5,
                        mitre_attack_id="T1055.001"
                    ))
            else:
                findings.append(DetectionFinding(
                    rule_name="Remote Thread Injection",
                    description="Process {} (PID {}) injected into {} (PID {})".format(
                        source_image, source_pid, target_image, target_pid
                    ),
                    severity=4,
                    mitre_attack_id="T1055.001"
                ))

        return findings

    def detect_api_hooking(self, events):
        findings = []
        process_dlls = {}

        for evt in events:
            if evt.get("event_type") != "DLL_LOAD":
                continue

            pid = evt.get("process_id")
            dll_name = evt.get("dll_name", "").lower()
            base_address = evt.get("base_address", "")

            if not pid:
                continue

            if pid not in process_dlls:
                process_dlls[pid] = []
            process_dlls[pid].append({"dll_name": dll_name, "base_address": base_address, "event": evt})

        for pid, dlls in process_dlls.items():
            for hook_dll in self.HOOKING_DLL_PATTERNS:
                hook_loads = [d for d in dlls if d["dll_name"] == hook_dll]
                if len(hook_loads) > 1:
                    findings.append(DetectionFinding(
                        rule_name="API Hooking Detected",
                        description="PID {} loaded {} {} times (potential re-hooking)".format(
                            pid, hook_dll, len(hook_loads)
                        ),
                        severity=4,
                        mitre_attack_id="T1055.004"
                    ))

            suspicious_dlls = [
                d for d in dlls
                if not d["dll_name"].endswith(".dll")
                or "temp" in d["dll_name"]
                or "appdata" in d["dll_name"].lower()
            ]
            if suspicious_dlls:
                dll_names = [d["dll_name"] for d in suspicious_dlls]
                findings.append(DetectionFinding(
                    rule_name="Suspicious DLL Load",
                    description="PID {} loaded suspicious DLLs: {}".format(pid, ", ".join(dll_names)),
                    severity=3,
                    mitre_attack_id="T1055.001"
                ))

        return findings

    def detect_lateral_movement(self, events):
        findings = []
        logon_events = {}
        process_events = []

        for evt in events:
            evt_type = evt.get("event_type", "")
            if evt_type == "LOGON":
                logon_type = evt.get("logon_type")
                source_ip = evt.get("source_ip", "")
                if logon_type in (3, 8, 9, 10) and source_ip and source_ip != "127.0.0.1" and source_ip != "::1":
                    logon_events[source_ip] = evt
            elif evt_type == "PROCESS_CREATED":
                process_events.append(evt)

        for source_ip, logon_evt in logon_events.items():
            for proc_evt in process_events:
                image = proc_evt.get("image_name", "").lower()
                cmdline = proc_evt.get("command_line", "").lower()
                suspicious_images = ["cmd.exe", "powershell.exe", "wmic.exe", "psexec.exe", "wmiapsrv.exe"]
                image_base = image.split("\\")[-1] if "\\" in image else image
                if image_base in suspicious_images:
                    findings.append(DetectionFinding(
                        rule_name="Lateral Movement",
                        description="Remote logon from {} followed by suspicious process {}".format(
                            source_ip, image_base
                        ),
                        severity=4,
                        mitre_attack_id="T1021.002"
                    ))
                    break

        return findings

    def detect_credential_access(self, events):
        findings = []
        lsass_targets = set()

        for evt in events:
            evt_type = evt.get("event_type", "")
            if evt_type == "PROCESS_ACCESS":
                target_pid = evt.get("target_pid")
                access_mask = evt.get("access_mask", "")
                source_pid = evt.get("source_pid")

                if target_pid in lsass_targets or (evt.get("target_image", "") or "").lower().endswith("lsass.exe"):
                    if target_pid:
                        lsass_targets.add(target_pid)

                    read_access_flags = ["0x0010", "0x0008", "0x00100000", "0x0400", "PROCESS_VM_READ"]
                    is_reading = any(flag in access_mask for flag in read_access_flags)

                    if is_reading and source_pid:
                        findings.append(DetectionFinding(
                            rule_name="Credential Access (LSASS)",
                            description="Process PID {} accessed lsass.exe (PID {}) with read permissions".format(
                                source_pid, target_pid
                            ),
                            severity=5,
                            mitre_attack_id="T1003.001"
                        ))

            if evt_type == "PROCESS_CREATED":
                image = (evt.get("image_name", "") or "").lower()
                cmdline = (evt.get("command_line", "") or "").lower()
                if "procdump" in image or "procdump" in cmdline:
                    if "lsass" in cmdline or "-ma" in cmdline:
                        findings.append(DetectionFinding(
                            rule_name="Credential Access (ProcDump)",
                            description="ProcDump used to dump process memory: {}".format(cmdline),
                            severity=5,
                            mitre_attack_id="T1003.001"
                        ))

        return findings

    def detect_suspicious_child_processes(self, events):
        findings = []
        process_map = {}

        for evt in events:
            if evt.get("event_type") != "PROCESS_CREATED":
                continue

            parent_pid = evt.get("parent_process_id")
            image_name = evt.get("image_name", "")
            image_base = image_name.split("\\")[-1] if "\\" in image_name else image_name
            child_lower = image_base.lower()

            if parent_pid and parent_pid in process_map:
                parent_image = process_map[parent_pid]
                parent_base = parent_image.split("\\")[-1] if "\\" in parent_image else parent_image
                parent_lower = parent_base.lower()

                if parent_lower in self.SUSPICIOUS_PARENT_CHILD:
                    suspicious_children = self.SUSPICIOUS_PARENT_CHILD[parent_lower]
                    if child_lower in suspicious_children:
                        findings.append(DetectionFinding(
                            rule_name="Suspicious Parent-Child Process",
                            description="{} (PID {}) spawned {} (PID {})".format(
                                parent_base, parent_pid, image_base, evt.get("process_id")
                            ),
                            severity=3,
                            mitre_attack_id="T1059.001"
                        ))

            pid = evt.get("process_id")
            if pid:
                process_map[pid] = image_name

        return findings

    def correlate_events(self, time_window_seconds=30):
        events_query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": "now-{}s".format(time_window_seconds)
                    }
                }
            },
            "sort": [{"timestamp": {"order": "asc"}}],
            "size": 1000
        }
        try:
            result = self.es.search(index="etw-telemetry*", body=events_query)
            events = [hit["_source"] for hit in result.get("hits", {}).get("hits", [])]
            return events
        except Exception:
            return []

    def run_detections(self, events=None):
        if events is None:
            events = self.correlate_events(time_window_seconds=300)

        all_findings = []
        all_findings.extend(self.detect_process_hollowing(events))
        all_findings.extend(self.detect_remote_thread_injection(events))
        all_findings.extend(self.detect_api_hooking(events))
        all_findings.extend(self.detect_lateral_movement(events))
        all_findings.extend(self.detect_credential_access(events))
        all_findings.extend(self.detect_suspicious_child_processes(events))

        all_findings.sort(key=lambda f: f.severity, reverse=True)
        return all_findings


def main():
    parser = argparse.ArgumentParser(description="ETW Detection Engine")
    parser.add_argument('--host', default='localhost', help='Elasticsearch host')
    parser.add_argument('--port', type=int, default=9200, help='Elasticsearch port')
    parser.add_argument('--time-window', type=int, default=300, help='Time window in seconds')
    args = parser.parse_args()

    engine = DetectionEngine(es_host=args.host, es_port=args.port)
    findings = engine.run_detections()

    print("Detection Results: {} findings".format(len(findings)))
    print("=" * 60)
    for f in findings:
        print("[SEV-{}] {} - {}".format(f.severity, f.rule_name, f.description))
        if f.mitre_attack_id:
            print("         MITRE ATT&CK: {}".format(f.mitre_attack_id))
        print()


if __name__ == '__main__':
    main()
