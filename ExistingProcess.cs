﻿using System.Diagnostics;
using System.Reflection;

using Microsoft.Win32.SafeHandles;

namespace FfxivArgLauncher;

/// <summary>
/// Class representing an already held process handle.
/// </summary>
internal class ExistingProcess : Process
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ExistingProcess"/> class.
    /// </summary>
    /// <param name="handle">The existing held process handle.</param>
    public ExistingProcess(IntPtr handle)
    {
        this.SetHandle(handle);
    }

    private void SetHandle(IntPtr handle)
    {
        var baseType = typeof(Process);
        if (baseType == null)
            return;
        var setProcessHandleMethod = baseType.GetMethod(
            "SetProcessHandle",
            BindingFlags.NonPublic | BindingFlags.Instance);
        setProcessHandleMethod?.Invoke(this, new object[] { new SafeProcessHandle(handle, true) });
    }
}
