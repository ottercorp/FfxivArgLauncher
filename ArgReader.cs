namespace FfxivArgLauncher;

using Iced.Intel;

using Reloaded.Memory.Sigscan;
using Reloaded.Memory.Sources;
using Serilog;
using System;
using System.Diagnostics;
using System.Linq;
using System.Text;

using Decoder = Iced.Intel.Decoder;

public sealed class LoginData : IEquatable<LoginData>
{
    public string[] Args;
    public string SessionId;
    public string SndaID;
    public string CommandLine;

    public bool Equals(LoginData? other)
    {
        if (other is null)
        {
            return false;
        }

        return this.SessionId == other.SessionId && this.SndaID == other.SndaID;
    }

    public override int GetHashCode() => (this.SndaID, this.SndaID).GetHashCode();

    public bool IsWegame()
    {
        if (Args.Contains("rail_zone_state=1"))
            return true;
        return false;
    }
}

public sealed class ArgReader
{
    private readonly Process targetProcess;
    private readonly bool disposeTargetProcess;
    private readonly ExternalMemory extMemory;
    private readonly Scanner scanner;

    private nuint gameWindowPtr = 0;

    public ArgReader(Process targetProcess, bool disposeTargetProcess = true)
    {
        this.targetProcess = targetProcess;
        this.disposeTargetProcess = disposeTargetProcess;
        this.extMemory = new ExternalMemory(targetProcess!.Handle);
        this.extMemory.ReadRaw((nuint)this.targetProcess.MainModule.BaseAddress, out var exeData, this.targetProcess.MainModule.ModuleMemorySize);
        this.scanner = new Scanner(exeData);
        this.GetGameWindowPtr();
    }

    public LoginData GetLoginData()
    {
        // 防止游戏启动过快导致没初始化好，虽然我从来没遇到过这种情况，但是有人遇到了 :(
        Thread.Sleep(1000);
        var data = new LoginData();
        ulong count = 0;
        int try_num = 20;
        while (try_num-- > 0 && count > 0)
        {
            this.extMemory.Read<ulong>(this.gameWindowPtr, out count);
            Thread.Sleep(1000);
        }

        this.extMemory.Read<ulong>(this.gameWindowPtr, out count);
        data.Args = new string[count];
        this.extMemory.Read<nuint>(this.gameWindowPtr + 8, out var argListPtr);
        for (int i = 0; i < (int)count; i++)
        {
            this.extMemory.Read<nuint>(argListPtr + (nuint)(8 * i), out var argPtr);
            var arg = ReadString(argPtr, Encoding.UTF8);
            Log.Information($"{argPtr:X},{arg}");
            data.Args[i] = arg;
        }

        if (!data.IsWegame())
        {
            Log.Information($"{targetProcess.Id} is not WeGame");
            return data;
        }

        for (int i = 0; i < 20; i++)
        {
            this.extMemory.Read<nuint>(this.gameWindowPtr + 0xA0, out var sidPtr, false);
            this.extMemory.Read<nuint>(this.gameWindowPtr + 0xA8, out var sndaIdPtr);
            this.extMemory.Read<nuint>(this.gameWindowPtr + 0xB8, out var cmdPtr);
            if (sidPtr == 0 || sndaIdPtr == 0)
            {
                Thread.Sleep(500);
                Log.Information($"try {i}: sidPtr:{sidPtr:X},sndaIdPtr:{sndaIdPtr:X}");
                continue;
            }

            data.SessionId = ReadString(sidPtr, Encoding.UTF8);
            data.SndaID = ReadString(sndaIdPtr, Encoding.UTF8);
            data.CommandLine = ReadString(cmdPtr, Encoding.UTF8);
            Log.Information($"SessionId:{sidPtr:X},{this.MaskString(data.SessionId)}");
            Log.Information($"SndaID:{sndaIdPtr:X},{this.MaskString(data.SndaID)}");
            Log.Information($"CommandLine:{cmdPtr:X},{data.CommandLine}");
            break;
        }

        return data;
    }

    public void KillProcess()
    {
        this.targetProcess?.Kill();
    }

    private string MaskString(string input)
    {
        if (string.IsNullOrEmpty(input) || input.Length <= 2)
        {
            return input.Length == 1 ? "*" : new string('*', input.Length);
        }

        int maskLength = input.Length - 2;
        return $"{input[0]}{new string('*', maskLength)}{input[input.Length - 1]}";
    }

    private string ReadString(nuint ptr, Encoding encoding, int maxLength = 256)
    {
        this.extMemory.SafeReadRaw(ptr, out var bytes, maxLength);
        var data = encoding.GetString(bytes);
        var eosPos = data.IndexOf('\0');
        return eosPos == -1 ? data : data.Substring(0, eosPos);
    }

    private void GetGameWindowPtr()
    {
        var sig = "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 44 38 64 24";
        var scan = this.scanner.FindPattern(sig);
        if (!scan.Found)
        {
            throw new Exception($"Can not find address for GameWindow:{sig}");
        }

        var address = (nuint)(this.targetProcess.MainModule!.BaseAddress + scan.Offset);

        this.extMemory.ReadRaw(address, out var orginBytes, 20);
        var codeReader = new ByteArrayCodeReader(orginBytes);
        var decoder = Decoder.Create(64, codeReader);
        decoder.IP = address;

        var bytesNum = 0;
        while (decoder.IP < decoder.IP + (nuint)orginBytes.Length)
        {
            var instr = decoder.Decode();
            if (instr.Code == Code.INVALID)
            {
                break;
            }

            if (instr.Code == Code.Lea_r64_m)
            {
                this.gameWindowPtr = (nuint)instr.IPRelativeMemoryAddress;
                break;
            }

            if (this.gameWindowPtr == 0)
            {
                throw new Exception($"Can not find address for GameWindow");
            }
        }
    }
}
