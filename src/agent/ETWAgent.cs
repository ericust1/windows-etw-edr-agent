using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace ETWAgent
{
    public class ProcessEvent
    {
        public int ProcessId { get; set; }
        public int ParentProcessId { get; set; }
        public string ImageName { get; set; }
        public string CommandLine { get; set; }
        public string CurrentDirectory { get; set; }
        public string EventType { get; set; }
        public DateTime Timestamp { get; set; }
        public int Severity { get; set; }
        public string Details { get; set; }
    }

    public class TelemetryEvent
    {
        [JsonPropertyName("process_id")]
        public int ProcessId { get; set; }

        [JsonPropertyName("parent_process_id")]
        public int ParentProcessId { get; set; }

        [JsonPropertyName("image_name")]
        public string ImageName { get; set; }

        [JsonPropertyName("command_line")]
        public string CommandLine { get; set; }

        [JsonPropertyName("current_directory")]
        public string CurrentDirectory { get; set; }

        [JsonPropertyName("event_type")]
        public string EventType { get; set; }

        [JsonPropertyName("timestamp")]
        public DateTime Timestamp { get; set; }

        [JsonPropertyName("severity")]
        public int Severity { get; set; }

        [JsonPropertyName("details")]
        public string Details { get; set; }

        [JsonPropertyName("hostname")]
        public string Hostname { get; set; }

        [JsonPropertyName("agent_version")]
        public string AgentVersion { get; set; }
    }

    public static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out IntPtr lpThreadId);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtCreateThreadEx(
            out IntPtr hThread,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool CreateSuspended,
            uint StackZeroBits,
            uint SizeOfStackCommit,
            uint SizeOfStackReserve,
            IntPtr lpAttributeList);

        public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        public const uint MEM_COMMIT = 0x00001000;
        public const uint MEM_RESERVE = 0x00002000;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_READWRITE = 0x04;
    }

    public class ETWAgent
    {
        private readonly HttpClient _httpClient;
        private readonly string _ingestionEndpoint;
        private readonly string _hostname;
        private readonly string _agentVersion;
        private readonly Dictionary<int, ProcessEvent> _trackedProcesses;
        private readonly ProcessHollowingDetector _hollowingDetector;
        private bool _isRunning;

        private const string KERNEL_PROCESS_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}";
        private const string SECURITY_AUDITING_GUID = "{54849625-5478-4994-A5BA-3E3B0328C30D}";

        public ETWAgent(string ingestionEndpoint = "http://localhost:8080/api/ingest")
        {
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            _ingestionEndpoint = ingestionEndpoint;
            _hostname = Environment.MachineName;
            _agentVersion = "1.0.0";
            _trackedProcesses = new Dictionary<int, ProcessEvent>();
            _hollowingDetector = new ProcessHollowingDetector();
            _isRunning = false;
        }

        public async Task StartMonitoring()
        {
            _isRunning = true;
            Console.WriteLine("[ETW Agent] Starting monitoring...");
            Console.WriteLine("[ETW Agent] Subscribing to Microsoft-Windows-Kernel-Process provider");
            Console.WriteLine("[ETW Agent] Subscribing to Microsoft-Windows-Security-Auditing provider");

            var kernelSession = new TraceEventSession("ETWAgent-KernelProcess", KERNEL_PROCESS_GUID);
            var securitySession = new TraceEventSession("ETWAgent-SecurityAudit", SECURITY_AUDITING_GUID);

            var kernelSource = new KernelProcessTraceEventParser(kernelSession.Source);
            kernelSource.ProcessCreated += OnProcessCreated;
            kernelSource.ProcessStopped += OnProcessDeleted;

            kernelSession.Source.Process();
            securitySession.Source.Process();

            Console.WriteLine("[ETW Agent] Monitoring active. Press Ctrl+C to stop.");
            await MonitorLoop();
        }

        private async Task MonitorLoop()
        {
            while (_isRunning)
            {
                await Task.Delay(1000);
            }
        }

        public void StopMonitoring()
        {
            _isRunning = false;
            Console.WriteLine("[ETW Agent] Stopping monitoring...");
        }

        private void OnProcessCreated(ProcessTraceData data)
        {
            try
            {
                var evt = new ProcessEvent
                {
                    ProcessId = data.ProcessID,
                    ParentProcessId = data.ParentID,
                    ImageName = data.ImageName,
                    CommandLine = data.CommandLine,
                    CurrentDirectory = data.CurrentDirectory,
                    EventType = "PROCESS_CREATED",
                    Timestamp = data.TimeStamp,
                    Severity = 0,
                    Details = ""
                };

                _trackedProcesses[evt.ProcessId] = evt;

                if (IsSuspiciousProcess(evt))
                {
                    evt.Severity = 3;
                    evt.Details = "Suspicious parent-child relationship detected";
                }

                var hollowingResult = _hollowingDetector.AnalyzeProcessCreation(evt);
                if (hollowingResult.IsSuspicious)
                {
                    evt.Severity = Math.Max(evt.Severity, 4);
                    evt.Details = string.IsNullOrEmpty(evt.Details)
                        ? hollowingResult.Reason
                        : evt.Details + "; " + hollowingResult.Reason;
                }

                WriteTelemetry(evt).Wait();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ETW Agent] Error in OnProcessCreated: {ex.Message}");
            }
        }

        private void OnProcessDeleted(ProcessTraceData data)
        {
            try
            {
                var evt = new ProcessEvent
                {
                    ProcessId = data.ProcessID,
                    ParentProcessId = 0,
                    ImageName = data.ImageName ?? "",
                    CommandLine = "",
                    CurrentDirectory = "",
                    EventType = "PROCESS_DELETED",
                    Timestamp = data.TimeStamp,
                    Severity = 0,
                    Details = ""
                };

                if (_trackedProcesses.ContainsKey(evt.ProcessId))
                {
                    _trackedProcesses.Remove(evt.ProcessId);
                }

                WriteTelemetry(evt).Wait();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ETW Agent] Error in OnProcessDeleted: {ex.Message}");
            }
        }

        public void OnRemoteThreadDetected(int sourcePid, int targetPid, IntPtr startAddress, IntPtr remoteThreadHandle)
        {
            var evt = new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = sourcePid,
                ImageName = GetProcessNameById(targetPid),
                CommandLine = "",
                CurrentDirectory = "",
                EventType = "REMOTE_THREAD_INJECTION",
                Timestamp = DateTime.UtcNow,
                Severity = 4,
                Details = string.Format(
                    "CreateRemoteThread detected: source PID {0} injected into target PID {1} at address 0x{2:X}",
                    sourcePid, targetPid, (ulong)startAddress)
            };

            var knownInjectors = new HashSet<string>
            {
                "svchost.exe", "csrss.exe", "lsass.exe", "smss.exe", "wininit.exe",
                "services.exe", "winlogon.exe", "dwm.exe"
            };

            string sourceName = GetProcessNameById(sourcePid);
            if (knownInjectors.Contains(sourceName?.ToLowerInvariant()))
            {
                evt.Severity = 5;
                evt.Details += " [CRITICAL: System process used as injector]";
            }

            WriteTelemetry(evt).Wait();
        }

        private bool IsSuspiciousProcess(ProcessEvent evt)
        {
            var suspiciousChildren = new Dictionary<string, HashSet<string>>
            {
                ["svchost.exe"] = new HashSet<string> { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe" },
                ["lsass.exe"] = new HashSet<string> { "cmd.exe", "powershell.exe", "unknown.exe" },
                ["csrss.exe"] = new HashSet<string> { "cmd.exe", "powershell.exe" },
                ["smss.exe"] = new HashSet<string> { "cmd.exe", "powershell.exe" },
                ["services.exe"] = new HashSet<string> { "cmd.exe", "powershell.exe", "rundll32.exe" }
            };

            string parentName = GetBaseName(evt.ImageName);

            if (_trackedProcesses.TryGetValue(evt.ParentProcessId, out var parentProc))
            {
                string parentImage = GetBaseName(parentProc.ImageName)?.ToLowerInvariant() ?? "";
                string childImage = GetBaseName(evt.ImageName)?.ToLowerInvariant() ?? "";

                if (suspiciousChildren.TryGetValue(parentImage, out var children) && children.Contains(childImage))
                {
                    return true;
                }
            }

            var knownSuspiciousPatterns = new string[]
                { "-encodedcommand", "-noprofile", "-windowstyle hidden", "-w hidden", "bypass", "downloadstring" };

            if (evt.CommandLine != null)
                foreach (var pattern in knownSuspiciousPatterns)
                    if (evt.CommandLine.ToLowerInvariant().Contains(pattern))
                        return true;

            return false;
        }

        private string GetProcessNameById(int pid)
        {
            try
            {
                var proc = Process.GetProcessById(pid);
                return proc.ProcessName + ".exe";
            }
            catch
            {
                return "unknown.exe";
            }
        }

        private string GetBaseName(string fullPath)
        {
            if (string.IsNullOrEmpty(fullPath)) return fullPath;
            int idx = fullPath.LastIndexOf('\\');
            return idx >= 0 ? fullPath.Substring(idx + 1) : fullPath;
        }

        public async Task WriteTelemetry(ProcessEvent evt)
        {
            try
            {
                var telemetry = new TelemetryEvent
                {
                    ProcessId = evt.ProcessId,
                    ParentProcessId = evt.ParentProcessId,
                    ImageName = evt.ImageName ?? "",
                    CommandLine = evt.CommandLine ?? "",
                    CurrentDirectory = evt.CurrentDirectory ?? "",
                    EventType = evt.EventType,
                    Timestamp = evt.Timestamp,
                    Severity = evt.Severity,
                    Details = evt.Details ?? "",
                    Hostname = _hostname,
                    AgentVersion = _agentVersion
                };

                string json = JsonSerializer.Serialize(telemetry);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync(_ingestionEndpoint, content);

                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine(string.Format(
                        "[ETW Agent] Telemetry send failed: {0} - {1}",
                        (int)response.StatusCode, response.ReasonPhrase));
                }
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine(string.Format("[ETW Agent] HTTP error sending telemetry: {0}", ex.Message));
            }
            catch (TaskCanceledException)
            {
                Console.WriteLine("[ETW Agent] Telemetry send timed out");
            }
        }
    }

    public class ProcessHollowingDetector
    {
        private readonly Dictionary<int, List<MemoryAllocationRecord>> _allocationMap;
        private readonly Dictionary<int, string> _originalImageMap;

        public ProcessHollowingDetector()
        {
            _allocationMap = new Dictionary<int, List<MemoryAllocationRecord>>();
            _originalImageMap = new Dictionary<int, string>();
        }

        public HollowingAnalysisResult AnalyzeProcessCreation(ProcessEvent evt)
        {
            _originalImageMap[evt.ProcessId] = evt.ImageName ?? "";

            if (_allocationMap.TryGetValue(evt.ProcessId, out var allocations))
            {
                if (allocations.Count > 0)
                {
                    bool hasExecAlloc = false;
                    ulong totalSize = 0;

                    foreach (var alloc in allocations)
                    {
                        totalSize += alloc.Size;
                        if (alloc.Protection == NativeMethods.PAGE_EXECUTE_READWRITE ||
                            alloc.Protection == NativeMethods.PAGE_READWRITE)
                        {
                            hasExecAlloc = true;
                        }
                    }

                    if (hasExecAlloc && totalSize > 4096)
                    {
                        _allocationMap.Remove(evt.ProcessId);
                        return new HollowingAnalysisResult
                        {
                            IsSuspicious = true,
                            Reason = string.Format(
                                "Process hollowing pattern: {0} bytes allocated with RWX permissions before process start",
                                totalSize)
                        };
                    }
                }

                _allocationMap.Remove(evt.ProcessId);
            }

            return new HollowingAnalysisResult { IsSuspicious = false, Reason = "" };
        }

        public void RecordAllocation(int targetPid, uint size, uint protection, IntPtr address)
        {
            if (!_allocationMap.ContainsKey(targetPid))
            {
                _allocationMap[targetPid] = new List<MemoryAllocationRecord>();
            }

            _allocationMap[targetPid].Add(new MemoryAllocationRecord
            {
                Size = size,
                Protection = protection,
                Address = address,
                Timestamp = DateTime.UtcNow
            });
        }

        public HollowingAnalysisResult CheckForImageReplacement(int pid, string newImageName)
        {
            if (_originalImageMap.TryGetValue(pid, out var originalImage))
            {
                if (!string.Equals(originalImage, newImageName, StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrEmpty(newImageName))
                {
                    return new HollowingAnalysisResult
                    {
                        IsSuspicious = true,
                        Reason = string.Format(
                            "Image replacement detected: original={0}, replacement={1}",
                            originalImage, newImageName)
                    };
                }
            }

            return new HollowingAnalysisResult { IsSuspicious = false, Reason = "" };
        }

        public void CleanupProcess(int pid)
        {
            _allocationMap.Remove(pid);
            _originalImageMap.Remove(pid);
        }
    }

    public struct MemoryAllocationRecord
    {
        public uint Size;
        public uint Protection;
        public IntPtr Address;
        public DateTime Timestamp;
    }

    public struct HollowingAnalysisResult
    {
        public bool IsSuspicious;
        public string Reason;
    }

    public class KernelProcessTraceEventParser
    {
        public event Action<ProcessTraceData> ProcessCreated;
        public event Action<ProcessTraceData> ProcessStopped;

        private readonly TraceEventSource _source;

        public KernelProcessTraceEventParser(TraceEventSource source)
        {
            _source = source;
        }
    }

    public class ProcessTraceData
    {
        public int ProcessID { get; set; }
        public int ParentID { get; set; }
        public string ImageName { get; set; }
        public string CommandLine { get; set; }
        public string CurrentDirectory { get; set; }
        public DateTime TimeStamp { get; set; }
    }

    public class TraceEventSource
    {
        public void Process() { }
    }

    public class TraceEventSession
    {
        public TraceEventSession(string name, string guid)
        {
            Name = name;
            Guid = guid;
            Source = new TraceEventSource();
        }

        public string Name { get; }
        public string Guid { get; }
        public TraceEventSource Source { get; }
    }

    public class Program
    {
        public static async Task Main(string[] args)
        {
            string endpoint = "http://localhost:8080/api/ingest";

            if (args.Length > 0)
            {
                endpoint = args[0];
            }

            var agent = new ETWAgent(endpoint);
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                agent.StopMonitoring();
            };

            await agent.StartMonitoring();
        }
    }
}
