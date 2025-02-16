namespace FfxivArgLauncher;

internal class Program
{
    static void Main(string[] args)
    {
        var noFixAcl = false;
        var waitForGameWindow = true;
        var gamePath = args[0];
        var gameArgumentString = args[1];
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
