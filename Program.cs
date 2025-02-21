namespace FfxivArgLauncher;
using Serilog;
using Serilog.Events;

internal class Program
{
    static void Main(string[] args)
    {
        Log.Logger = new LoggerConfiguration()
                     .WriteTo.Console(standardErrorFromLevel: LogEventLevel.Fatal)
                     .MinimumLevel.Verbose()
                     .CreateLogger();

        var noFixAcl = false;
        var waitForGameWindow = true;
        var gamePath = args[0];
        var gameArgumentString = string.Empty;
        if (args.Length == 2)
        {
            gameArgumentString = args[1];
        }
        else
        {
            List<string> gameArguments = new();
            gameArguments.InsertRange(0, new string[]
                {
                    //"DEV.TestSID=114514",
                    "XL.SndaId=OTTER",
                    "DEV.UseSqPack=1",
                    "DEV.DataPathType=1",
                    "DEV.LobbyHost01=127.0.0.1",
                    "DEV.LobbyPort01=54994",
                    "DEV.LobbyHost02=127.0.0.2",
                    "DEV.LobbyPort02=54994",
                    "DEV.LobbyHost03=127.0.0.3",
                    "DEV.LobbyPort03=54994",
                    "DEV.LobbyHost04=127.0.0.4",
                    "DEV.LobbyPort04=54994",
                    "DEV.LobbyHost05=127.0.0.5",
                    "DEV.LobbyPort05=54994",
                    "DEV.LobbyHost06=127.0.0.6",
                    "DEV.LobbyPort06=54994",
                    "DEV.LobbyHost07=127.0.0.7",
                    "DEV.LobbyPort07=54994",
                    "DEV.LobbyHost08=127.0.0.8",
                    "DEV.LobbyPort08=54994",
                    "DEV.LobbyHost09=127.0.0.9",
                    "DEV.LobbyPort09=54994",
                    "SYS.Region=0",
                    $"language=5",
                    $"ver=2012.01.01",
                    $"DEV.MaxEntitledExpansionID=5",
                    "DEV.GMServerHost=127.0.0.100",
                    "DEV.GameQuitMessageBox=0",
                  });
            gameArgumentString = string.Join(" ", gameArguments);
        }

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
