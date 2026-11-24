using System.Drawing;
using Reloaded.Hooks.ReloadedII.Interfaces;
using Reloaded.Mod.Interfaces;
using Reloaded.Mod.Interfaces.Internal;

namespace p3rpc.rtssfix;

public sealed class Mod : IMod
{
    private RtssOverlayFix? _fix;
    public Action Disposing => () => { };

    public void StartEx(IModLoaderV1 loaderApi, IModConfigV1 modConfig)
    {
        var logger = loaderApi.GetLogger();

        if (!Environment.Is64BitProcess)
        {
            logger.PrintMessage("[p3rpc.rtssfix] Skipping: 64-bit process required.", Color.Yellow);
            return;
        }

        var hooksController = loaderApi.GetController<IReloadedHooks>();
        if (hooksController == null || !hooksController.TryGetTarget(out var hooks) || hooks == null)
        {
            logger.PrintMessage("[p3rpc.rtssfix] Failed to acquire IReloadedHooks from reloaded.sharedlib.hooks.", Color.Red);
            return;
        }

        if (RtssOverlayFix.IsRtssAlreadyLoaded())
        {
            logger.PrintMessage("[p3rpc.rtssfix] Warning: RTSSHooks64.dll was already loaded before this mod initialized; move this mod higher in Reloaded-II load order.", Color.Yellow);
        }

        _fix = new RtssOverlayFix(hooks);
        logger.PrintMessage($"[p3rpc.rtssfix] Active on {_fix.TargetModule}!GetModuleHandleA (0x{_fix.TargetAddress:X}).", Color.LightGreen);
    }

    public void Start(IModLoaderV1 loaderApi) => StartEx(loaderApi, null!);
    public void Suspend() => _fix?.Disable();
    public void Resume() => _fix?.Enable();
    public void Unload() => _fix?.Dispose();
    public bool CanUnload() => false;
    public bool CanSuspend() => true;
}
