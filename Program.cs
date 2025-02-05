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
        foreach (var item in args)
        {
            Console.WriteLine(item);
        }

        switch (args.Length)
        {
            case 3:
                {
                    if (args[0] == "launch")
                    {
                        var noFixAcl = true;
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
                    }

                    break;
                }

            default:
                {
                    throw new Exception("Error args");
                    break;
                }
        }
    }
}
