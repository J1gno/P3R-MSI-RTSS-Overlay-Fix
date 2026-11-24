# P3R RTSS Overlay Fix (`p3rpc.rtssfix`)

Reloaded-II mod for **Persona 3 Reload** (`p3r.exe`) that allows the MSI Afterburner / RivaTuner Statistics Server (RTSS) overlay to attach and render when launching the game through Reloaded-II.

## Why It's Needed

Some Reloaded-II mods (such as `p3rpc.expGainEditor`) include a WPF configurator window, which causes .NET to map `PresentationFramework.dll` into `P3R.exe` when Reloaded-II scans mod assemblies. RTSS's default `InjectionIgnoreTriggers` list (`PresentationFramework.dll`, `PresentationFramework.NI.dll`, `Microsoft.WinUI.dll`) causes `RTSSHooks64.dll` to abort hooking.

This mod installs a pure-native x64 hook on `kernelbase.dll!GetModuleHandleA` (via `Reloaded.Hooks`) that returns `NULL` (`ERROR_MOD_NOT_FOUND`) for those three trigger DLL names while leaving all other `GetModuleHandleA` and `GetModuleHandleW` calls untouched.

## Dependencies

- [Reloaded.SharedLib.Hooks](https://github.com/Sewer56/Reloaded.SharedLib.Hooks.ReloadedII) (`reloaded.sharedlib.hooks`)

## Building from Source

Requires the .NET 9+ SDK on Windows x64:

```powershell
dotnet build p3rpc.rtssfix.csproj -c Release -p:Platform=x64
```
