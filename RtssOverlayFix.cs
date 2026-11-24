using System.Runtime.InteropServices;
using System.Text;
using Reloaded.Hooks.Definitions;
using Reloaded.Hooks.Definitions.Enums;

namespace p3rpc.rtssfix;

/// <summary>
/// Installs a pure-native x64 hook on GetModuleHandleA so RTSS's InjectionIgnoreTriggers
/// check does not abort hooking when Reloaded-II mods map PresentationFramework.dll.
/// Pure native ASM avoids CLR/GC transitions under the Windows OS loader lock (DllMain).
/// </summary>
public sealed class RtssOverlayFix : IDisposable
{
    private const string DummyModuleName = "__p3r_rtss_bypass__.dll";

    // Matches RTSS ProfileTemplates\Global [Hooking] InjectionIgnoreTriggers (lowercase ASCII).
    private static readonly string[] IgnoredTriggerModules =
    [
        "presentationframework.dll",
        "presentationframework.ni.dll",
        "microsoft.winui.dll",
    ];

    private readonly IAsmHook _hook;
    private IntPtr _nativeStrings;
    private bool _disposed;

    public string TargetModule { get; }
    public nint TargetAddress { get; }

    public RtssOverlayFix(IReloadedHooks hooks)
    {
        ArgumentNullException.ThrowIfNull(hooks);

        (TargetModule, TargetAddress) = ResolveGetModuleHandleA();
        if (TargetAddress == 0)
            throw new InvalidOperationException("Failed to resolve GetModuleHandleA in kernelbase.dll or kernel32.dll.");

        var (buffer, dummyAddr, tableAddr) = AllocateNativeStrings();
        _nativeStrings = buffer;

        try
        {
            // Pure-native x64 filter executed before GetModuleHandleA's prologue.
            // Uses only Windows x64 ABI volatile registers (rax, rdx, r8, r9, r10).
            string[] asm =
            [
                "use64",
                "test rcx, rcx",
                "jz done",
                // Fast-path: reject unless first char is 'p'/'P' or 'm'/'M'.
                "mov al, byte [rcx]",
                "or al, 0x20",
                "cmp al, 0x70",
                "je scan_start",
                "cmp al, 0x6D",
                "jne done",

                "scan_start:",
                $"mov r8, 0x{tableAddr:X}",

                "next_candidate:",
                "cmp byte [r8], 0",
                "je done",
                "mov r9, rcx",
                "mov r10, r8",

                "cmp_loop:",
                "mov al, byte [r9]",
                "mov dl, byte [r10]",
                "cmp al, 0x41",
                "jb no_lower",
                "cmp al, 0x5A",
                "ja no_lower",
                "add al, 0x20",

                "no_lower:",
                "cmp al, dl",
                "jne mismatch",
                "test dl, dl",
                "jz matched",
                "inc r9",
                "inc r10",
                "jmp cmp_loop",

                "mismatch:",
                "mov r8, r10",
                "skip_null:",
                "cmp byte [r8], 0",
                "je advance_past_null",
                "inc r8",
                "jmp skip_null",
                "advance_past_null:",
                "inc r8",
                "jmp next_candidate",

                "matched:",
                $"mov rcx, 0x{dummyAddr:X}",

                "done:",
            ];

            _hook = hooks.CreateAsmHook(asm, (long)TargetAddress, AsmHookBehaviour.ExecuteFirst).Activate();
        }
        catch
        {
            Marshal.FreeHGlobal(_nativeStrings);
            _nativeStrings = IntPtr.Zero;
            throw;
        }
    }

    public void Enable() => _hook.Enable();
    public void Disable() => _hook.Disable();

    public static bool IsRtssAlreadyLoaded() => GetModuleHandleW("RTSSHooks64.dll") != 0;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _hook.Disable();
        // shortcut: keep unmanaged string buffer allocated after Disable() rather than synchronizing in-flight native callers; safe because Reloaded-II mods do not unload.
    }

    private static (string Module, nint Address) ResolveGetModuleHandleA()
    {
        // Hook kernelbase.dll directly: kernel32!GetModuleHandleA is a 7-byte JMP thunk into kernelbase.
        nint kernelBase = GetModuleHandleW("kernelbase.dll");
        if (kernelBase != 0)
        {
            nint addr = GetProcAddress(kernelBase, "GetModuleHandleA");
            if (addr != 0) return ("kernelbase.dll", addr);
        }

        nint kernel32 = GetModuleHandleW("kernel32.dll");
        if (kernel32 != 0)
        {
            nint addr = GetProcAddress(kernel32, "GetModuleHandleA");
            if (addr != 0) return ("kernel32.dll", addr);
        }

        return (string.Empty, 0);
    }

    private static (IntPtr Buffer, ulong DummyAddr, ulong TableAddr) AllocateNativeStrings()
    {
        var dummyBytes = Encoding.ASCII.GetBytes(DummyModuleName + "\0");
        var tableBuilder = new List<byte>();
        foreach (var name in IgnoredTriggerModules)
        {
            tableBuilder.AddRange(Encoding.ASCII.GetBytes(name));
            tableBuilder.Add(0);
        }
        tableBuilder.Add(0); // double-null terminator for table end
        var tableBytes = tableBuilder.ToArray();

        int tableOffset = (dummyBytes.Length + 7) & ~7;
        IntPtr buffer = Marshal.AllocHGlobal(tableOffset + tableBytes.Length);
        Marshal.Copy(dummyBytes, 0, buffer, dummyBytes.Length);
        Marshal.Copy(tableBytes, 0, buffer + tableOffset, tableBytes.Length);

        return (buffer, (ulong)buffer, (ulong)(buffer + tableOffset));
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint GetModuleHandleW(string lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    private static extern nint GetProcAddress(nint hModule, string procName);
}
