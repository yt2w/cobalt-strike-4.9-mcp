#!/usr/bin/env python3
"""bof_scanner.py -- dependency-free static risk scanner for Cobalt Strike BOFs.

The scanner is deliberately *static*: it never imports, links, loads or executes
anything from the corpus it inspects.  It only reads bytes from disk and runs
regular expressions over the resulting text.

Public API
----------
scan_source(path) -> dict
    Scan a source file (.c/.cpp/.h/.cs) as text.
scan_object(path) -> dict
    Scan a compiled COFF/ELF object (.o) by extracting printable ASCII runs.
classify(findings) -> dict
    Turn a finding list into {"risk", "score", "categories", "reasons"}.

Every scan result has the shape:
    {"path": str, "kind": "source"|"object", "findings": [...], "missing": bool}
and every finding has the shape:
    {"rule": str, "severity": "low"|"medium"|"high", "category": str,
     "evidence": str}

Risk model
----------
RISK_WEIGHTS maps a finding severity onto point values.  The score of a BOF is
the sum of the *maximum* severity weight found in each distinct category (so a
file calling forty injection APIs is not automatically critical) plus explicit
combination bonuses for known high-signal patterns (remote injection triad,
process hollowing).  Policy floors guarantee the documented calibration:

    * pure discovery (no injection, no execution)  -> low
    * process execution (CreateProcess/WinExec/ps) -> high
    * AMSI/ETW patching                             -> high
    * VirtualAlloc + WriteProcessMemory + CreateRemoteThread -> critical
"""

from __future__ import annotations

import os
import re

__all__ = [
    "scan_source",
    "scan_object",
    "scan_path",
    "scan_bof",
    "classify",
    "extract_strings",
    "find_source_for_object",
    "RULES",
    "RISK_WEIGHTS",
    "RISK_BANDS",
    "MAX_SOURCE_BYTES",
    "MIN_STRING_LEN",
]

# --------------------------------------------------------------------------
# Tunables
# --------------------------------------------------------------------------

MAX_SOURCE_BYTES = 2 * 1024 * 1024   # scan at most 2 MB of a source file
MIN_STRING_LEN = 4                   # minimum printable run kept from an object

#: severity -> score points
RISK_WEIGHTS = {"low": 2, "medium": 5, "high": 10}

#: minimum score required to land in a band (checked high -> low)
RISK_BANDS = {"low": 0, "medium": 10, "high": 20, "critical": 40}

# --------------------------------------------------------------------------
# Rule table
# --------------------------------------------------------------------------
# Each entry: (id, category, severity, pattern, requires, description)
#   requires: optional tuple of regexes that must *all* match somewhere in the
#             same file/text before the rule is reported.
#   All patterns are matched case-insensitively.

_RULE_SPECS = (
    # ---------------- process hollowing / injection ----------------
    ("INJ_VIRTUAL_ALLOC", "process_hollowing", "medium",
     r"\bVirtualAlloc\b", (),
     "Allocates memory (often RWX) for staged shellcode"),
    ("INJ_VIRTUAL_ALLOC_EX", "process_hollowing", "high",
     r"\bVirtualAllocEx\b", (),
     "Allocates memory in a remote process - classic injection primitive"),
    ("INJ_VIRTUAL_PROTECT", "process_hollowing", "medium",
     r"\bVirtualProtect(?:Ex)?\b", (),
     "Changes memory page permissions (frequently used to make code RWX)"),
    ("INJ_WRITE_PROCESS_MEMORY", "process_hollowing", "high",
     r"\bWriteProcessMemory\b", (),
     "Writes into another process's address space - remote code injection"),
    ("INJ_NT_WRITE_VIRTUAL_MEMORY", "process_hollowing", "high",
     r"\bNtWriteVirtualMemory\b", (),
     "Writes into another process via ntdll syscall stub"),
    ("INJ_CREATE_REMOTE_THREAD", "process_hollowing", "high",
     r"\bCreateRemoteThread(?:Ex)?\b", (),
     "Starts a thread in a remote process - remote code injection"),
    ("INJ_NT_CREATE_THREAD_EX", "process_hollowing", "high",
     r"\bNtCreateThreadEx\b", (),
     "Creates a thread in a remote process via ntdll"),
    ("INJ_RTL_CREATE_USER_THREAD", "process_hollowing", "high",
     r"\bRtlCreateUserThread\b", (),
     "Creates a user thread in a remote process via ntdll"),
    ("INJ_QUEUE_USER_APC", "process_hollowing", "high",
     r"\bQueueUserAPC\b", (),
     "Queues an APC in a remote thread - APC injection"),
    ("INJ_NT_QUEUE_APC_THREAD", "process_hollowing", "high",
     r"\bNtQueueApcThread\b", (),
     "Queues an APC in a remote thread via ntdll - APC injection"),
    ("INJ_SET_THREAD_CONTEXT", "process_hollowing", "high",
     r"\bSetThreadContext\b", (),
     "Rewrites a thread context - used to redirect execution"),
    ("INJ_NT_SET_CONTEXT_THREAD", "process_hollowing", "high",
     r"\bNtSetContextThread\b", (),
     "Rewrites a thread context via ntdll"),
    ("INJ_NT_MAP_VIEW_OF_SECTION", "process_hollowing", "high",
     r"\bNtMapViewOfSection\b", (),
     "Maps a section into a process - process hollowing / injection"),
    ("INJ_ZW_UNMAP_VIEW_OF_SECTION", "process_hollowing", "high",
     r"\bZwUnmapViewOfSection\b", (),
     "Unmaps a section from a process - hallmark of process hollowing"),
    ("INJ_NT_UNMAP_VIEW_OF_SECTION", "process_hollowing", "high",
     r"\bNtUnmapViewOfSection\b", (),
     "Unmaps a section from a process - hallmark of process hollowing"),
    ("INJ_NT_ALLOCATE_VIRTUAL_MEMORY", "process_hollowing", "high",
     r"\bNtAllocateVirtualMemory\b", (),
     "Allocates memory via ntdll syscall stub"),
    ("INJ_NT_PROTECT_VIRTUAL_MEMORY", "process_hollowing", "high",
     r"\bNtProtectVirtualMemory\b", (),
     "Changes page permissions via ntdll syscall stub"),
    ("INJ_NT_READ_VIRTUAL_MEMORY", "process_hollowing", "medium",
     r"\bNtReadVirtualMemory\b", (),
     "Reads another process's address space via ntdll"),
    ("INJ_READ_PROCESS_MEMORY", "process_hollowing", "medium",
     r"\bReadProcessMemory\b", (),
     "Reads another process's address space (memory scraping)"),
    ("INJ_BEACON_INJECT_PROCESS", "process_hollowing", "high",
     r"\bBeaconInjectProcess\b|\bBeaconInjectTemporaryProcess\b", (),
     "Beacon remote process injection API - injects a payload into a process"),
    ("INJ_BEACON_SPAWN_TEMPORARY", "process_hollowing", "high",
     r"\bBeaconSpawnTemporaryProcess\b", (),
     "Beacon temporary-process spawn - process hollowing helper"),
    ("INJ_BEACON_CLEANUP_PROCESS", "process_hollowing", "medium",
     r"\bBeaconCleanupProcess\b", (),
     "Beacon cleanup of a hollowed/injected process"),
    ("INJ_OPEN_PROCESS_RIGHTS", "process_hollowing", "high",
     r"\bOpenProcess\b",
     (r"\bPROCESS_(?:CREATE_THREAD|VM_WRITE|VM_OPERATION)\b"),
     "Opens a process with thread/write rights - injection intent"),

    # ---------------- defense evasion ----------------
    ("EVASION_AMSI_SCAN_BUFFER", "defense_evasion", "medium",
     r"\bAmsiScanBuffer\b", (),
     "Touches the AMSI scan path (probing, hooking or patching)"),
    ("EVASION_ETW_EVENT_WRITE", "defense_evasion", "medium",
     r"\bEtwEventWrite\b", (),
     "Writes ETW events (often used to suppress or fake telemetry)"),
    ("EVASION_NT_TRACE_EVENT", "defense_evasion", "medium",
     r"\bNtTraceEvent\b", (),
     "Calls the ETW provider entrypoint via ntdll"),
    ("EVASION_SECURITY_DLL_PATCH", "defense_evasion", "high",
     r"(?:\b(?:amsi|etw|ntdll)(?:\.dll)?\b[^\n]{0,80}\b(?:patch\w*|unhook\w*|overwrit\w*|hook\w*)\b)"
     r"|(?:\b(?:patch\w*|unhook\w*|overwrit\w*|hook\w*)\b[^\n]{0,80}\b(?:amsi|etw|ntdll)(?:\.dll)?\b)",
     (),
     "Patches/unhooks a security provider (amsi/etw/ntdll) - classic EDR bypass"),
    ("EVASION_UNHOOK_DLL", "defense_evasion", "high",
     r"\bUnhook(?:Dll|Function)\b", (),
     "Unhooks a hooked function from a security product"),
    ("EVASION_APC_THREAD_CHAIN", "defense_evasion", "high",
     r"\bSuspendThread\b", (r"\bNtQueueApcThread\b",),
     "SuspendThread + NtQueueApcThread APC injection chain"),
    ("EVASION_NTDLL_SYSCALL_STUB", "defense_evasion", "medium",
     r"\bSysWhispers\b|\bsyscall\s+stub\b|\bsyscalls?[-_.]asm\b|\bSW2_PopulateSyscallList\b"
     r"|\bFunctionHash\b|\bsyscall\s+with\s+hash\b|\bHashedSyscall\w*\b",
     (),
     "Builds direct syscalls (SysWhispers style) to hide API calls"),
    ("EVASION_AV_PROCESS_TARGET", "defense_evasion", "medium",
     r"\bMsMpEng(?:\.exe)?\b|\bMpEngineHost\b|\bSenseiEngine\b|\bCSFalconService\b"
     r"|\bSophos(?:File|Agent)?Service\b|\bCylanceSvc\b|\bWdNisSvc\b|\bWindows Defender\b"
     r"|\bCrowdStrike\b|\bSentinelOne\b|\bCarbonBlack\b",
     (),
     "Targets or enumerates endpoint security products (AV/EDR processes)"),
    ("EVASION_AV_PROCESS_TERMINATE", "defense_evasion", "high",
     r"\b(?:TerminateProcess|NtTerminateProcess)\b",
     (r"\b(?:MsMpEng|MpEngineHost|SenseiEngine|CSFalconService|Sophos|CylanceSvc|WdNisSvc|CrowdStrike|SentinelOne|CarbonBlack)\b"),
     "Terminates an endpoint security process - direct AV/EDR takedown"),
    ("EVASION_ETW_PATCH_NTDLL", "defense_evasion", "high",
     r"\b(?:NtTraceEvent|EtwEventWrite)\b[^\n]{0,120}\b(?:patch|unhook|overwrit)\b"
     r"|\b(?:patch|unhook|overwrit)\w*\b[^\n]{0,120}\b(?:NtTraceEvent|EtwEventWrite)\b",
     (),
     "Patches the ETW provider path to blind EDR telemetry"),
    ("EVASION_DEFENDER_DISABLE", "defense_evasion", "high",
     r"\b(?:DisableAntiSpyware|DisableRealtimeMonitoring|MpPreference|Set-MpPreference|WdFilter|WdNisSvc)\b",
     (r"\b(?:RegSetValue\w*|RegCreateKey\w*|WriteFile|sc\s+config|service\s+config|PowerShell|Set-MpPreference|DisableAntiSpyware)\b"),
     "Manipulates Microsoft Defender settings (write action)"),

    # ---------------- persistence ----------------
    ("PERSIST_REG_RUN_KEY", "persistence", "high",
     r"\bRegSetValueEx\w*\b[^\n]{0,160}\b(?:Run|RunOnce)\b"
     r"|\b(?:Run|RunOnce)\b[^\n]{0,160}\bRegSetValueEx\w*\b",
     (),
     "Writes a Run/RunOnce registry value - autostart persistence"),
    ("PERSIST_REG_SERVICE_KEY", "persistence", "high",
     r"\bRegSetValueEx\w*\b[^\n]{0,160}\bServices?\b"
     r"|\bServices?\b[^\n]{0,160}\bRegSetValueEx\w*\b",
     (),
     "Writes a service registry key - service persistence"),
    ("PERSIST_CREATE_SERVICE", "persistence", "high",
     r"\b(?:CreateService[AW]?|ChangeServiceConfig[AW]?|StartService[AW]?)\b", (),
     "Creates or reconfigures a Windows service - persistence"),
    ("PERSIST_SCHTASKS", "persistence", "high",
     r"\bschtasks(?:\.exe)?\b|\bScheduledTask\b|\bITaskScheduler\b", (),
     "Scheduled task creation/inspection - task based persistence"),
    ("PERSIST_STARTUP_FOLDER", "persistence", "medium",
     r"\bStart Menu\\Programs\\Startup\b|\bPrograms\\Startup\b|\bStartup folder\b|\bStartup\\", (),
     "Writes into a Startup folder - autostart persistence"),
    ("PERSIST_WMI_EVENT", "persistence", "medium",
     r"\b__EventFilter\b|\bCommandLineEventConsumer\b|\bActiveScriptEventConsumer\b", (),
     "WMI event subscription - fileless persistence"),

    # ---------------- credential access ----------------
    ("CRED_LSASS", "credential_access", "high",
     r"\blsass(?:\.exe)?\b|\bLSASS\b",
     (r"\b(?:OpenProcess|NtOpenProcess|ReadProcessMemory|NtReadVirtualMemory|CreateToolhelp32Snapshot|TerminateProcess|DumpProcessMemory|procdump|AdjustTokenPrivileges|NtAdjustPrivilegesToken)\b"),
     "Reads the LSASS process - credential dumping target"),
    ("CRED_LSASS_REF", "credential_access", "low",
     r"\blsass(?:\.exe)?\b|\bLSASS\b", (),
     "Mentions the LSASS process (may be enumeration or policy text)"),
    ("CRED_MIMIKATZ", "credential_access", "high",
     r"\bmimikatz\b|\bsekurlsa\b|\blogonpasswords\b", (),
     "Mimikatz-style credential extraction"),
    ("CRED_SEKURSA", "credential_access", "high",
     r"\bsekurlsa\b|\bkerberos::|\bmsv1_0\b", (),
     "Kerberos credential extraction (sekurlsa / msv1_0)"),
    ("CRED_WDIGEST", "credential_access", "medium",
     r"\bwdigest\b|\bWDigest\b", (),
     "References WDigest credential material"),
    ("CRED_VAULT", "credential_access", "medium",
     r"\bWindowsVault\b|\bCredEnumerate\w*\b|\bVaultEnumerate\w*\b|\bVAULT_", (),
     "Enumerates the Windows credential vault"),
    ("CRED_GENERIC", "credential_access", "low",
     r"\bcredential\w*\b|\bcred(?:s|ential)\b|\bpassword\w*\b", (),
     "Generic credential/password handling"),
    ("CRED_DPAPI", "credential_access", "medium",
     r"\bCryptUnprotectData\b|\bDPAPI\b|\bDPAPI\w*\b|\bdpapi\b", (),
     "DPAPI blob decryption (credential material)"),
    ("CRED_SAM_CONNECT", "credential_access", "medium",
     r"\bSamConnect\b|\bSamOpenDomain\b|\bSAM\w*Handle", (),
     "Queries the local SAM - credential database access"),
    ("CRED_OPEN_PROCESS_VM_READ", "credential_access", "medium",
     r"\bOpenProcess\b", (r"\bPROCESS_VM_READ\b",),
     "Opens a process with VM_READ rights - memory scraping for secrets"),
    ("CRED_NTLM", "credential_access", "medium",
     r"\bNetUserGetInfo\b|\bLsaRetrievePrivateData\b|\bCredEnumerate\w*\b|\bPPL\b|\bProtected\s*Process\b", (),
     "Queries account/credential material via LSA or SAM APIs"),

    # ---------------- discovery / noise ----------------
    ("DISC_ENUM_PROCESSES", "discovery_noise", "low",
     r"\bEnumProcesses\b|\bK32EnumProcesses\b", (),
     "Enumerates running processes (discovery noise)"),
    ("DISC_TOOLHELP_SNAPSHOT", "discovery_noise", "low",
     r"\bCreateToolhelp32Snapshot\b", (),
     "Toolhelp process/module snapshot (discovery noise)"),
    ("DISC_ADAPTERS", "discovery_noise", "low",
     r"\bGetAdaptersInfo\w*\b|\bGetAdaptersAddresses\b", (),
     "Enumerates network adapters (discovery noise)"),
    ("DISC_NET_USER_ENUM", "discovery_noise", "low",
     r"\bNetUserEnum\b|\bNetUserGetInfo\b", (),
     "Enumerates local/domain users (discovery noise)"),
    ("DISC_WHOAMI", "discovery_noise", "low",
     r"\bwhoami\b|\bWHOAMI\b", (),
     "whoami style identity check (discovery noise)"),
    ("DISC_MODULE_ENUM", "discovery_noise", "low",
     r"\bEnumProcessModules\w*\b|\bK32EnumProcessModules\b|\bEnumProcessModulesEx\b", (),
     "Enumerates loaded modules (discovery noise)"),
    ("DISC_LOCAL_GROUP_ENUM", "discovery_noise", "low",
     r"\bNetLocalGroupEnum\b|\bNetGroupEnum\b", (),
     "Enumerates local groups (discovery noise)"),
    ("DISC_SESSION_ENUM", "discovery_noise", "low",
     r"\bWTSEnumerateSessions\w*\b|\bWTSEnumerateUsers\w*\b|\bNetSessionEnum\b", (),
     "Enumerates sessions/users (discovery noise)"),
    ("DISC_BEACON_IS_ADMIN", "discovery_noise", "low",
     r"\bBeaconIsAdmin\b", (),
     "Beacon admin check (discovery noise)"),

    # ---------------- execution ----------------
    ("EXEC_CREATE_PROCESS", "execution", "high",
     r"\bCreateProcess[AW]?\b|\bCreateProcessAsUser[AW]?\b", (),
     "Spawns a child process - classic EDR execution signal"),
    ("EXEC_WINEXEC", "execution", "high",
     r"\bWinExec\b", (),
     "Legacy process execution API"),
    ("EXEC_SHELL_EXECUTE", "execution", "high",
     r"\bShellExecute[AW]?\b|\bShellExecuteEx[AW]?\b", (),
     "Shell execution API"),
    ("EXEC_SYSTEM", "execution", "high",
     r"\bsystem\s*\(|\bpopen\s*\(|\bexecve?\s*\(", (),
     "C runtime process execution (system/popen/exec)"),
    ("EXEC_POWERSHELL", "execution", "high",
     r"\bpowershell(?:\.exe)?\b|\bpwsh(?:\.exe)?\b", (),
     "PowerShell invocation - high fidelity execution signal"),
    ("EXEC_CMD", "execution", "high",
     r"\bcmd\.exe\b|\bcmd\s+/[ck]\b", (),
     "cmd.exe invocation - high fidelity execution signal"),
    ("EXEC_RUNDLL32", "execution", "high",
     r"\brundll32(?:\.exe)?\b", (),
     "rundll32 invocation - proxy execution"),
    ("EXEC_REGSVR32", "execution", "high",
     r"\bregsvr32(?:\.exe)?\b", (),
     "regsvr32 invocation - proxy execution"),
    ("EXEC_WMI_PROCESS", "execution", "high",
     r"\bWin32_Process\b|\bInvoke-CimMethod\b|\bIWbemServices\b|\bExecMethod\b", (),
     "WMI/CIM process creation - fileless execution"),
    ("EXEC_MSBUILD", "execution", "high",
     r"\bmsbuild(?:\.exe)?\b|\binstallutil(?:\.exe)?\b|\bcsc\.exe\b|\bmshta(?:\.exe)?\b", (),
     "Trusted signed-binary proxy execution"),

    # ---------------- privilege ----------------
    ("PRIV_ADJUST_TOKEN_PRIVILEGES", "privilege", "medium",
     r"\bAdjustTokenPrivileges\b|\bNtAdjustPrivilegesToken\b", (),
     "Adjusts token privileges (escalation)"),
    ("PRIV_SE_DEBUG", "privilege", "medium",
     r"\bSeDebugPrivilege\b", (),
     "References the SeDebugPrivilege token right"),
    ("PRIV_IMPERSONATE_LOGGED_ON_USER", "privilege", "medium",
     r"\bImpersonateLoggedOnUser\b|\bImpersonateNamedPipeClient\b", (),
     "Impersonation API - token/context abuse"),
    ("PRIV_DUPLICATE_TOKEN", "privilege", "medium",
     r"\bDuplicateToken(?:Ex)?\b|\bDuplicateHandle\b", (),
     "Duplicates a token/handle - privilege escalation primitive"),
    ("PRIV_SET_TOKEN_INFORMATION", "privilege", "medium",
     r"\bSetTokenInformation\b|\bNtSetInformationToken\b", (),
     "Rewrites token information - privilege manipulation"),
    ("PRIV_CREATE_PROCESS_AS_USER", "privilege", "medium",
     r"\bCreateProcessAsUser[AW]?\b|\bLogonUser[AW]?\b|\bImpersonateClient\b", (),
     "Runs code under another user's token"),
    ("PRIV_BEACON_TOKEN", "privilege", "medium",
     r"\bBeaconUseToken\b|\bBeaconRevertToken\b", (),
     "Beacon token manipulation - runs code under another identity"),

    # ---------------- network ----------------
    ("NET_WSA_STARTUP", "network", "low",
     r"\bWSAStartup\b|\bWSACleanup\b", (),
     "Winsock initialisation - network capability"),
    ("NET_CONNECT", "network", "low",
     r"\bconnect\b", (),
     "Socket connect - network capability"),
    ("NET_SEND", "network", "low",
     r"\bsend\b|\bsendto\b|\bWSA(?:Send|SendTo)\b", (),
     "Socket send - network capability"),
    ("NET_WINHTTP", "network", "low",
     r"\bWinHttpOpen\b|\bWinHttpConnect\b|\bWinHttpSendRequest\b", (),
     "WinHTTP client - network capability"),
    ("NET_INTERNET_OPEN", "network", "low",
     r"\bInternetOpen[AW]?\b|\bInternetConnect[AW]?\b|\bHttpOpenRequest[AW]?\b", (),
     "WinINet client - network capability"),
    ("NET_SOCKET", "network", "low",
     r"\bsocket\b|\baccept\b|\bbind\b|\blisten\b", (),
     "Raw socket usage - network capability"),
    ("NET_URL_DOWNLOAD", "network", "medium",
     r"\bURLDownloadToFile\w*\b|\bInternetReadFile\b|\bHttpSendRequest\w*\b", (),
     "Downloads content to disk over HTTP"),

    # ---------------- artifact on disk ----------------
    ("ART_FOPEN", "artifact_on_disk", "low",
     r"\bfopen\b|\bfopen64\b|\bfreopen\b", (),
     "Opens a file on disk"),
    ("ART_CREATE_FILE", "artifact_on_disk", "low",
     r"\bCreateFile[AW]?\b", (),
     "Creates/opens a file on disk"),
    ("ART_WRITE_FILE", "artifact_on_disk", "low",
     r"\bWriteFile\b|\bfwrite\b|\bfputs\b|\bWriteFileEx\b", (),
     "Writes data to disk"),
    ("ART_OFSTREAM", "artifact_on_disk", "low",
     r"\bofstream\b", (),
     "C++ ofstream file output - artifact on disk"),
    ("ART_FSTREAM", "artifact_on_disk", "low",
     r"\bfstream\b", (),
     "C++ fstream file input/output - artifact on disk"),
    ("ART_FILE_WRITE_COMBO", "artifact_on_disk", "low",
     r"\bWriteFile\b", (r"\bCreateFile[AW]?\b",),
     "Opens and writes a file - artifact dropped on disk"),
    ("ART_TEMP_DROP", "artifact_on_disk", "medium",
     r"\b(?:WriteFile|CopyFile[AW]?|MoveFile[AW]?)\b[^\n]{0,120}(?:%TEMP%|\\Temp\\|/tmp/)"
     r"|(?:%TEMP%|\\Temp\\|/tmp/)[^\n]{0,120}\b(?:WriteFile|CopyFile[AW]?|MoveFile[AW]?)\b",
     (),
     "Drops a file into a temp directory - classic staging behaviour"),
    ("ART_EXE_DROP", "artifact_on_disk", "medium",
     r"\.(?:dll|exe|sys)\b[^\n]{0,80}\b(?:WriteFile|CopyFile[AW]?|MoveFile[AW]?)\b"
     r"|\b(?:WriteFile|CopyFile[AW]?|MoveFile[AW]?)\b[^\n]{0,80}\.(?:dll|exe|sys)\b", (),
     "Writes an executable/library to disk"),

    # ---------------- anti-forensics ----------------
    ("AF_TIMESTOMP", "anti_forensics", "medium",
     r"\btime[-_ ]?stomp\w*\b|\btimestomp\w*\b", (),
     "Timestamp stomping - timestomping artefacts"),
    ("AF_SET_FILE_TIME", "anti_forensics", "medium",
     r"\bSetFileTime\b|\bNtSetInformationFile\b[^\n]{0,60}\bFileTime\b", (),
     "Rewrites file timestamps"),
    ("AF_CLEAR_EVENT_LOG", "anti_forensics", "high",
     r"\bClearEventLog\w*\b|\bClearEventLog\b", (),
     "Clears Windows event logs - anti-forensics"),
    ("AF_WEVTUTIL", "anti_forensics", "medium",
     r"\bwevtutil(?:\.exe)?\b", (),
     "Event log utility usage - log manipulation"),
    ("AF_DELETE_SHADOW", "anti_forensics", "medium",
     r"\bvssadmin(?:\.exe)?\b[^\n]{0,100}\b(?:delete|shadow)\b"
     r"|\b(?:delete|shadow)\b[^\n]{0,100}\bvssadmin(?:\.exe)?\b"
     r"|\bwmic\b[^\n]{0,80}\bshadowcopy\b",
     (),
     "Deletes volume shadow copies - anti-forensics"),
    ("AF_DELETE_FILE", "anti_forensics", "low",
     r"\bDeleteFile[AW]?\b|\bRemoveDirectory\w*\b|\bSHFileOperation\w*\b", (),
     "Deletes files/directories - possible trace removal"),
    ("AF_ARTIFACT_TIDY", "anti_forensics", "medium",
     r"\b(?:delete|remove|clean(?:up)?)\b[^\n]{0,80}\b(?:artifact|trace|evidence)\b"
     r"|\b(?:artifact|trace|evidence)\b[^\n]{0,80}\b(?:delete|remove|clean(?:up)?)\b",
     (),
     "Deletes artefacts/evidence - anti-forensics"),

    # ---------------- BOF loader / sleepmask notes ----------------
    ("EXEC_LOADER_ENTRY", "EXEC_LOADER", "low",
     r"\bgo\s*\(\s*(?:char|CHAR|void|VOID|unsigned\s+char)\b", (),
     "Standalone BOF entry point (go + bof_pack style) - may spawn a loader"),
    ("SLEEP_MASK_REF", "SLEEP_MASK", "low",
     r"\bsleepmask\b|\bsleep\s*mask\b|\bmask(?:ing)?\s+image\b", (),
     "References a sleepmask (in-memory masking / evasion framework)"),
)


def _literals(pattern):
    """Extract literal words from a regex so scans can pre-filter cheaply."""
    stripped = re.sub(r"\[\^?[^\]]*\]", " ", pattern)
    # drop escape sequences (\b, \., \n, \s, ...) so they do not glue onto
    # the following word ("\bVirtualAlloc" must yield "virtualalloc")
    stripped = re.sub(r"\\.", " ", stripped)
    return tuple(sorted(
        {m.group(0).lower() for m in re.finditer(r"[A-Za-z_][A-Za-z0-9_]{3,}", stripped)},
        key=len, reverse=True))


class Rule(object):
    """A single detection rule."""

    __slots__ = ("rule", "category", "severity", "description",
                 "pattern", "requires", "prefilter")

    def __init__(self, rule, category, severity, pattern, requires, description):
        self.rule = rule
        self.category = category
        self.severity = severity
        self.description = description
        self.pattern = re.compile(pattern, re.IGNORECASE)
        if isinstance(requires, str):
            requires = (requires,)
        self.requires = tuple(re.compile(r, re.IGNORECASE) for r in requires)
        self.prefilter = _literals(pattern)

    def __repr__(self):  # pragma: no cover - debug helper
        return "<Rule %s [%s/%s]>" % (self.rule, self.category, self.severity)


RULES = tuple(Rule(*spec) for spec in _RULE_SPECS)

RULES_BY_ID = {r.rule: r for r in RULES}


# --------------------------------------------------------------------------
# Low level helpers
# --------------------------------------------------------------------------

def extract_strings(data, min_len=MIN_STRING_LEN):
    """Extract printable ASCII runs from *data* and return them as text."""
    if isinstance(data, str):
        data = data.encode("latin-1", "replace")
    runs = re.findall(rb"[ -~]{%d,}" % int(min_len), data)
    return "\n".join(r.decode("latin-1") for r in runs)


def _evidence(text, match, width=160):
    """Return a short, single-line evidence snippet around *match*."""
    start = max(0, match.start() - 48)
    end = min(len(text), match.end() + 96)
    snippet = " ".join(text[start:end].split())
    if len(snippet) > width:
        snippet = snippet[:width - 3] + "..."
    return snippet


def _scan_text(text):
    """Run every rule over *text* and return a list of findings."""
    findings = []
    lowered = text.lower()
    for rule in RULES:
        if rule.prefilter and not any(lit in lowered for lit in rule.prefilter):
            continue
        m = rule.pattern.search(text)
        if not m:
            continue
        ok = True
        for req in rule.requires:
            if not req.search(text):
                ok = False
                break
        if not ok:
            continue
        findings.append({
            "rule": rule.rule,
            "severity": rule.severity,
            "category": rule.category,
            "evidence": _evidence(text, m),
        })
    return findings


def _missing(path, kind):
    return {"path": path, "kind": kind, "findings": [], "missing": True}


# --------------------------------------------------------------------------
# Public scanning API
# --------------------------------------------------------------------------

def scan_source(path):
    """Statically scan a source file (.c/.cpp/.h/.cs) for risky behaviour."""
    path = os.fspath(path)
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_SOURCE_BYTES)
    except (OSError, ValueError):
        return _missing(path, "source")
    text = data.decode("utf-8", "replace")
    return {
        "path": path,
        "kind": "source",
        "findings": _scan_text(text),
        "missing": False,
    }


def scan_object(path):
    """Statically scan a compiled object (.o) via printable-string extraction."""
    path = os.fspath(path)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except (OSError, ValueError):
        return _missing(path, "object")
    text = extract_strings(data)
    return {
        "path": path,
        "kind": "object",
        "findings": _scan_text(text),
        "missing": False,
    }


# --------------------------------------------------------------------------
# Risk classification
# --------------------------------------------------------------------------

_ALLOC_RULES = ("INJ_VIRTUAL_ALLOC", "INJ_VIRTUAL_ALLOC_EX", "INJ_NT_ALLOCATE_VIRTUAL_MEMORY")
_WRITE_RULES = ("INJ_WRITE_PROCESS_MEMORY", "INJ_NT_WRITE_VIRTUAL_MEMORY")
_THREAD_RULES = ("INJ_CREATE_REMOTE_THREAD", "INJ_NT_CREATE_THREAD_EX",
                 "INJ_RTL_CREATE_USER_THREAD", "INJ_QUEUE_USER_APC")
_UNMAP_RULES = ("INJ_ZW_UNMAP_VIEW_OF_SECTION", "INJ_NT_UNMAP_VIEW_OF_SECTION")
_MAP_RULES = ("INJ_NT_MAP_VIEW_OF_SECTION", "INJ_WRITE_PROCESS_MEMORY",
              "INJ_NT_WRITE_VIRTUAL_MEMORY")

_EXECUTION_RULES = tuple(r.rule for r in RULES if r.category == "execution")
_PATCH_RULES = ("EVASION_SECURITY_DLL_PATCH", "EVASION_UNHOOK_DLL",
                "EVASION_ETW_PATCH_NTDLL")
_HIGH_INJECTION_RULES = tuple(r.rule for r in RULES
                              if r.category == "process_hollowing" and r.severity == "high")
# "soft" rules only mention a concept - they must not raise the policy floor
_WEAK_CRED_RULES = ("CRED_GENERIC", "CRED_LSASS_REF")
_WEAK_EVASION_RULES = ("EVASION_AV_PROCESS_TARGET",)
_STRONG_CRED_RULES = tuple(r.rule for r in RULES
                            if r.category == "credential_access" and r.rule not in _WEAK_CRED_RULES)
_STRONG_EVASION_RULES = tuple(r.rule for r in RULES
                               if r.category == "defense_evasion" and r.rule not in _WEAK_EVASION_RULES)


def _band_for(score):
    band = "low"
    for name in ("medium", "high", "critical"):
        if score >= RISK_BANDS[name]:
            band = name
    return band


def classify(findings):
    """Classify a list of findings into a risk band, score and reasons."""
    findings = list(findings or [])
    by_cat = {}
    for f in findings:
        by_cat.setdefault(f.get("category", "unknown"), []).append(f)

    score = 0
    reasons = []
    for cat in sorted(by_cat):
        fs = by_cat[cat]
        weight = max(RISK_WEIGHTS.get(f.get("severity", "low"), 1) for f in fs)
        score += weight
        ids = sorted({f.get("rule", "?") for f in fs})
        reasons.append("%s: %s" % (cat, ", ".join(ids)))

    present = {f.get("rule") for f in findings}
    cats = set(by_cat)

    # --- combination bonuses ------------------------------------------------
    if present & set(_ALLOC_RULES) and present & set(_WRITE_RULES) and present & set(_THREAD_RULES):
        score += 30
        reasons.append("classic remote injection triad (alloc + remote write + remote thread)")

    if present & set(_UNMAP_RULES) and present & set(_MAP_RULES):
        score += 15
        reasons.append("process hollowing pattern (unmap section + map/write image)")

    if present & set(_PATCH_RULES):
        score += 5
        reasons.append("security provider patching (amsi/etw/ntdll)")

    # --- policy floors (calibration) ---------------------------------------
    if cats & {"execution"}:
        score = max(score, RISK_BANDS["high"])
        reasons.append("executes a child process / script (policy: high)")

    if present & set(_PATCH_RULES):
        score = max(score, RISK_BANDS["high"])
        reasons.append("amsi/etw patching (policy: high)")

    if present & set(_HIGH_INJECTION_RULES):
        score = max(score, RISK_BANDS["high"])
        reasons.append("remote injection primitive present (policy: high)")

    if "EVASION_AV_PROCESS_TERMINATE" in present:
        score = max(score, RISK_BANDS["high"])
        reasons.append("terminates an AV/EDR process (policy: high)")

    if present & set(_STRONG_CRED_RULES):
        score = max(score, RISK_BANDS["medium"])
        reasons.append("credential access surface (policy: at least medium)")

    if present & set(_STRONG_EVASION_RULES):
        score = max(score, RISK_BANDS["medium"])
        reasons.append("defense evasion surface (policy: at least medium)")

    if "persistence" in cats:
        score = max(score, RISK_BANDS["medium"])
        reasons.append("persistence surface (policy: at least medium)")

    if "anti_forensics" in cats:
        score = max(score, RISK_BANDS["medium"])
        reasons.append("anti-forensics surface (policy: at least medium)")

    score = int(score)
    band = _band_for(score)
    if band == "critical" and not any("triad" in r for r in reasons):
        reasons.append("critical risk band reached")
    if not reasons:
        reasons.append("no risky indicators detected")

    return {
        "risk": band,
        "score": score,
        "categories": sorted(cats),
        "reasons": reasons,
    }


# --------------------------------------------------------------------------
# Source discovery helpers (convenience for inventory builders / MCP servers)
# --------------------------------------------------------------------------

_ARCH_SUFFIX_RE = re.compile(r"(?i)(x64|x86|amd64|win64|win32|i386)$")
_SOURCE_INDEX_CACHE = {}


def _norm_stem(path):
    """Normalise a file stem: drop the path, the arch suffix and punctuation."""
    stem = os.path.basename(os.path.splitext(path)[0])
    stem = _ARCH_SUFFIX_RE.sub("", stem) or stem
    return re.sub(r"[^a-z0-9]", "", stem.lower())


def _kit_of(path, root):
    rel = os.path.relpath(path, root)
    parts = rel.split(os.sep)
    return parts[0] if len(parts) > 1 else "<root>"


def _build_source_index(root):
    """Index every .c/.cpp source below *root* by (kit, normalised stem)."""
    cached = _SOURCE_INDEX_CACHE.get(root)
    if cached is not None:
        return cached
    index = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            if name.lower().endswith((".c", ".cpp")):
                path = os.path.join(dirpath, name)
                index.setdefault((_kit_of(path, root), _norm_stem(path)), []).append(path)
    _SOURCE_INDEX_CACHE[root] = index
    return index


def find_source_for_object(obj_path, corpus_root):
    """Return the most likely source file for a compiled object, or None.

    Matching is deliberately conservative:
      1. same directory, identical (arch-normalised) stem  -> best signal
      2. same top level "kit", identical (arch-normalised) stem -> good signal
    Ties are broken by the longest shared path prefix so that duplicated kit
    copies resolve to the closest source tree.
    """
    obj_path = os.path.abspath(obj_path)
    root = os.path.abspath(corpus_root)
    stem = _norm_stem(obj_path)
    obj_dir = os.path.dirname(obj_path)

    index = _build_source_index(root)
    candidates = list(index.get((_kit_of(obj_path, root), stem), []))
    same_dir = [c for c in candidates if os.path.dirname(c) == obj_dir]
    if same_dir:
        candidates = same_dir
    if not candidates:
        return None
    candidates.sort(key=lambda c: (-len(os.path.commonprefix([obj_dir, os.path.dirname(c)])), c))
    return candidates[0]


def scan_path(path):
    """Dispatch to :func:`scan_source` or :func:`scan_object` by extension."""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".cs"):
        return scan_source(path)
    return scan_object(path)


def scan_bof(object_path, corpus_root=None):
    """Scan a compiled BOF, preferring source findings when a source exists.

    The source sibling is scanned first (it is the most readable artefact) but
    findings that only exist in the compiled object are kept as well: many
    kits spread their implementation over several files, so a single source
    file under-reports what the object actually does.

    Returns the scan result plus:
        "source_path"      absolute path of the source used (or None)
        "object_only_rules" rules that only the object revealed
        "classification"   output of :func:`classify`
    """
    obj_path = os.path.abspath(object_path)
    obj_res = scan_object(obj_path)
    source_path = None
    src_findings = []
    if corpus_root:
        candidate = find_source_for_object(obj_path, corpus_root)
        if candidate:
            src_res = scan_source(candidate)
            if not src_res["missing"]:
                source_path = candidate
                src_findings = src_res["findings"]

    findings = list(src_findings)
    seen = {f["rule"] for f in src_findings}
    object_only = []
    for finding in obj_res["findings"]:
        if finding["rule"] not in seen:
            seen.add(finding["rule"])
            findings.append(finding)
            object_only.append(finding["rule"])

    result = {
        "path": obj_path,
        "kind": "source" if source_path else "object",
        "findings": findings,
        "missing": obj_res["missing"],
        "source_path": source_path,
        "object_only_rules": object_only,
    }
    result["classification"] = classify(findings)
    return result


# --------------------------------------------------------------------------
# Convenience CLI (read-only; prints JSON to stdout)
# --------------------------------------------------------------------------

def _main(argv):  # pragma: no cover - convenience only
    import json
    import sys
    if not argv:
        print("usage: bof_scanner.py <file> [file ...]", file=sys.stderr)
        return 2
    out = []
    for path in argv:
        if path.lower().endswith((".c", ".cpp", ".h", ".cs", ".hpp", ".cc")):
            res = scan_source(path)
        else:
            res = scan_object(path)
        res["classification"] = classify(res["findings"])
        out.append(res)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys
    sys.exit(_main(sys.argv[1:]))
