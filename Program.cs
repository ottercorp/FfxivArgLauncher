using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Dalamud.Injector;
using Reloaded.Memory.Buffers;
using Serilog;
namespace FfxivArgLauncher;

internal class Program
{
    static void Main(string[] args)
    {
        // launch gamePath argments
        // read pid channelName

        switch (args[0])
        {
            case "launch":
                {
                    var noFixAcl = false;
                    var waitForGameWindow = true;
                    var gamePath = args[1];
                    var gameArgumentString = args[2];
                    var process = GameStart.LaunchGame(
                        Path.GetDirectoryName(gamePath),
                        gamePath,
                        gameArgumentString,
                        noFixAcl,
                        p =>
                        {
                            var argFixer = new ArgFixer(p);
                            argFixer.Fix();
                        },
                        waitForGameWindow);

                    break;
                }

            case "read":
                {
                    var process = Process.GetProcessById(int.Parse(args[1]));
                    var argReader = new ArgReader(process);
                    break;
                }
            default:
                throw new Exception("Error args");
        }
    }
}
