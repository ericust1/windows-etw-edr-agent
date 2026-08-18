import argparse
import json
import random
import string
from datetime import datetime, timezone, timedelta


class ETWEventGenerator:
    def __init__(self):
        self.base_time = datetime.now(timezone.utc)

    def _generate_timestamp(self, offset_seconds=0):
        return (self.base_time + timedelta(seconds=offset_seconds)).isoformat()

    def _random_hex(self, length=8):
        return ''.join(random.choices(string.hexdigits.lower(), k=length))

    def generate_process_create(self, pid, ppid, image, cmdline, current_dir):
        return {
            "process_id": pid,
            "parent_process_id": ppid,
            "image_name": image,
            "command_line": cmdline,
            "current_directory": current_dir,
            "event_type": "PROCESS_CREATED",
            "timestamp": self._generate_timestamp(),
            "severity": 0,
            "details": ""
        }

    def generate_process_access(self, target_pid, source_pid, access_mask):
        return {
            "process_id": source_pid,
            "source_pid": source_pid,
            "target_pid": target_pid,
            "access_mask": access_mask,
            "target_image": "\\Device\\HarddiskVolume2\\Windows\\System32\\lsass.exe",
            "event_type": "PROCESS_ACCESS",
            "timestamp": self._generate_timestamp(),
            "severity": 0,
            "details": ""
        }

    def generate_remote_thread(self, source_pid, target_pid, start_address):
        return {
            "process_id": target_pid,
            "parent_process_id": source_pid,
            "source_pid": source_pid,
            "target_pid": target_pid,
            "start_address": start_address,
            "source_image": "\\Device\\HarddiskVolume2\\Windows\\System32\\svchost.exe",
            "image_name": "\\Device\\HarddiskVolume2\\Windows\\System32\\notepad.exe",
            "event_type": "REMOTE_THREAD_INJECTION",
            "timestamp": self._generate_timestamp(),
            "severity": 4,
            "details": "CreateRemoteThread: source PID {} injected into target PID {} at address {}".format(
                source_pid, target_pid, start_address
            )
        }

    def generate_dll_load(self, pid, dll_name, base_address):
        return {
            "process_id": pid,
            "dll_name": dll_name,
            "base_address": base_address,
            "event_type": "DLL_LOAD",
            "timestamp": self._generate_timestamp(),
            "severity": 0,
            "details": ""
        }

    def generate_logon_event(self, sid, logon_type, source_ip, target_computer):
        return {
            "sid": sid,
            "logon_type": logon_type,
            "source_ip": source_ip,
            "target_computer": target_computer,
            "event_type": "LOGON",
            "timestamp": self._generate_timestamp(),
            "severity": 0,
            "details": ""
        }

    def generate_attack_scenario(self, scenario_name):
        events = []
        gen = ETWEventGenerator

        if scenario_name == 'process_hollowing':
            events.append(self.generate_process_create(
                pid=1234, ppid=500,
                image="C:\\Windows\\System32\\svchost.exe",
                cmdline="svchost.exe -k netsvcs",
                current_dir="C:\\Windows\\System32"
            ))
            events.append(self.generate_remote_thread(
                source_pid=5678, target_pid=1234,
                start_address="0x" + self._random_hex(16)
            ))
            events.append({
                "process_id": 1234,
                "parent_process_id": 500,
                "image_name": "C:\\Windows\\Temp\\malware.exe",
                "command_line": "",
                "current_directory": "",
                "event_type": "PROCESS_CREATED",
                "timestamp": self._generate_timestamp(offset_seconds=2),
                "severity": 0,
                "details": ""
            })

        elif scenario_name == 'credential_dumping':
            events.append(self.generate_process_create(
                pid=9999, ppid=1234,
                image="C:\\Windows\\System32\\cmd.exe",
                cmdline="cmd.exe /c procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp",
                current_dir="C:\\Users\\admin\\Downloads"
            ))
            events.append(self.generate_process_access(
                target_pid=668, source_pid=9999,
                access_mask="0x0010|0x0008|0x00100000"
            ))
            events.append(self.generate_process_create(
                pid=10000, ppid=9999,
                image="C:\\temp\\procdump.exe",
                cmdline="procdump.exe -ma 668 C:\\temp\\lsass.dmp",
                current_dir="C:\\Users\\admin\\Downloads"
            ))

        elif scenario_name == 'lateral_movement':
            events.append(self.generate_logon_event(
                sid="S-1-5-21-1000000000-2000000000-3000000000-5001",
                logon_type=3,
                source_ip="10.0.0.55",
                target_computer="WORKSTATION-01"
            ))
            events.append(self.generate_process_create(
                pid=3456, ppid=789,
                image="C:\\Windows\\System32\\cmd.exe",
                cmdline="cmd.exe /c whoami",
                current_dir="C:\\Windows\\System32"
            ))
            events.append(self.generate_process_create(
                pid=3457, ppid=3456,
                image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                cmdline="powershell.exe -encodedcommand JABjAGwAaQBlAG4AdAA",
                current_dir="C:\\Windows\\System32"
            ))

        elif scenario_name == 'api_hooking':
            events.append(self.generate_process_create(
                pid=4444, ppid=1000,
                image="C:\\Program Files\\SuspiciousApp\\app.exe",
                cmdline="app.exe",
                current_dir="C:\\Program Files\\SuspiciousApp"
            ))
            events.append(self.generate_dll_load(
                pid=4444,
                dll_name="ntdll.dll",
                base_address="0x7FFE" + self._random_hex(8)
            ))
            events.append(self.generate_dll_load(
                pid=4444,
                dll_name="ntdll.dll",
                base_address="0x7FFE" + self._random_hex(8)
            ))
            events.append(self.generate_dll_load(
                pid=4444,
                dll_name="user32.dll",
                base_address="0x7FFE" + self._random_hex(8)
            ))
            events.append(self.generate_dll_load(
                pid=4444,
                dll_name="C:\\Users\\admin\\AppData\\Local\\Temp\\hook.dll",
                base_address="0x7FFE" + self._random_hex(8)
            ))

        elif scenario_name == 'remote_thread_injection':
            events.append(self.generate_process_create(
                pid=7777, ppid=500,
                image="C:\\Windows\\System32\\notepad.exe",
                cmdline="notepad.exe",
                current_dir="C:\\Windows\\System32"
            ))
            events.append(self.generate_remote_thread(
                source_pid=8888, target_pid=7777,
                start_address="0x" + self._random_hex(16)
            ))

        return events


def main():
    parser = argparse.ArgumentParser(description="ETW Event Generator")
    parser.add_argument('--scenario', required=True,
                        choices=['process_hollowing', 'credential_dumping', 'lateral_movement',
                                 'api_hooking', 'remote_thread_injection'],
                        help='Attack scenario to generate')
    parser.add_argument('--pretty', action='store_true', help='Pretty print JSON')
    args = parser.parse_args()

    generator = ETWEventGenerator()
    events = generator.generate_attack_scenario(args.scenario)

    indent = 2 if args.pretty else None
    print(json.dumps(events, indent=indent))


if __name__ == '__main__':
    main()
