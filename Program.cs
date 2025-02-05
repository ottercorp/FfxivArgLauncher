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
        Console.WriteLine("Hello, World!");
        var noFixAcl = true;
        var waitForGameWindow = true;
        var gamePath = "D:\\Games\\FFXIV\\sdo\\sdologin\\..\\..\\game\\ffxiv_dx11.exe";
        var gameArgumentString = "-AppID=100001900 -AreaID=7 Dev.LobbyHost01=ffxivlobby07.ff14.sdo.com Dev.LobbyPort01=54994 Dev.GMServerHost=ffxivgm07.ff14.sdo.com Dev.SaveDataBankHost=ffxivsdb07.ff14.sdo.com resetConfig=0 DEV.MaxEntitledExpansionID=1 XL.SndaId=1111 DEV.TestSID=OTTER-114514";
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
}
