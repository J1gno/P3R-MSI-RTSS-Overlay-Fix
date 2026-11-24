using System.Runtime.InteropServices;
using Reloaded.Hooks;
using p3rpc.rtssfix;

[DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
static extern nint GetModuleHandleA(string? lpModuleName);

[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
static extern nint GetModuleHandleW(string? lpModuleName);

static void Assert(bool condition, string message)
{
    if (!condition)
        throw new Exception("ASSERT FAILED: " + message);
}

// 1. Force PresentationFramework.dll and PresentationCore.dll to load into this process,
// mirroring Reloaded-II calling Assembly.GetTypes() on p3rpc.expGainEditor.dll.
Console.WriteLine($"Loaded: {typeof(System.Windows.Window).Assembly.GetName().Name}, {typeof(System.Windows.Media.Visual).Assembly.GetName().Name}");
nint pfBeforeA = GetModuleHandleA("PresentationFramework.dll");
nint pfBeforeW = GetModuleHandleW("PresentationFramework.dll");
nint pcBeforeA = GetModuleHandleA("PresentationCore.dll");
Console.WriteLine($"Before hook: PF(A)=0x{pfBeforeA:X}, PF(W)=0x{pfBeforeW:X}, PC(A)=0x{pcBeforeA:X}");
Assert(pfBeforeA != 0, "Expected PresentationFramework.dll to be mapped before hook.");
Assert(pfBeforeW != 0, "Expected GetModuleHandleW(PresentationFramework.dll) != 0.");

// 2. Install our native x64 hook using real Reloaded.Hooks.
using var fix = new RtssOverlayFix(ReloadedHooks.Instance);
Console.WriteLine($"Hooked {fix.TargetModule}!GetModuleHandleA at 0x{fix.TargetAddress:X}");

// 3. Verify masked RTSS trigger names return NULL + ERROR_MOD_NOT_FOUND (126).
const int ERROR_MOD_NOT_FOUND = 126;
foreach (var name in new[]
{
    "PresentationFramework.dll",
    "PRESENTATIONFRAMEWORK.DLL",
    "presentationframework.dll",
    "PresentationFramework.NI.dll",
    "Microsoft.WinUI.dll",
    "MICROSOFT.WINUI.DLL",
})
{
    nint h = GetModuleHandleA(name);
    int err = Marshal.GetLastWin32Error();
    Assert(h == 0, $"Expected GetModuleHandleA({name}) == 0, got 0x{h:X}");
    Assert(err == ERROR_MOD_NOT_FOUND, $"Expected ERROR_MOD_NOT_FOUND (126) for {name}, got {err}");
}

// 4. Verify non-trigger lookups remain completely untouched.
Assert(GetModuleHandleA(null) == GetModuleHandleW(null) && GetModuleHandleA(null) != 0, "NULL module lookup broke.");
Assert(GetModuleHandleA("") == 0, "Empty string lookup should return 0.");
Assert(GetModuleHandleA("kernel32.dll") != 0, "kernel32.dll lookup broke.");
Assert(GetModuleHandleA("kernelbase.dll") != 0, "kernelbase.dll lookup broke.");
Assert(GetModuleHandleA("ntdll.dll") != 0, "ntdll.dll lookup broke.");
if (pcBeforeA != 0)
    Assert(GetModuleHandleA("PresentationCore.dll") == pcBeforeA, "PresentationCore.dll (same 'P' prefix) must not be masked.");
Assert(GetModuleHandleW("PresentationFramework.dll") == pfBeforeW, "Unicode GetModuleHandleW must remain untouched.");

// 5. Verify concurrent calls across threads do not race or corrupt registers.
Parallel.For(0, 2000, i =>
{
    if ((i & 1) == 0)
        Assert(GetModuleHandleA("PresentationFramework.dll") == 0, "Concurrent masked call failed.");
    else
        Assert(GetModuleHandleA("kernel32.dll") != 0, "Concurrent unmasked call failed.");
});

// 6. Verify Disable/Enable restores and re-applies cleanly.
fix.Disable();
Assert(GetModuleHandleA("PresentationFramework.dll") == pfBeforeA, "Disable() did not restore original behavior.");
fix.Enable();
Assert(GetModuleHandleA("PresentationFramework.dll") == 0, "Enable() did not re-enable masking.");

Console.WriteLine("ALL SELF-TESTS PASSED.");
