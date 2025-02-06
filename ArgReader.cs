namespace FfxivArgLauncher;

using Iced.Intel;
using PeNet.Header.Resource;
using Reloaded.Memory.Buffers;
using Reloaded.Memory.Buffers.Internal.Testing;
using Reloaded.Memory.Sigscan;
using Reloaded.Memory.Sources;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Decoder = Iced.Intel.Decoder;

internal class ArgReader
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

    public List<string> GetArgs()
    {
        this.extMemory.Read<ulong>(this.gameWindowPtr,out var count);
        var args = new List<string>((int)count);
        this.extMemory.Read<nuint>(this.gameWindowPtr + 8, out var argListPtr);
        for (int i = 0; i < (int)count; i++)
        {
            this.extMemory.Read<nuint>(argListPtr + (nuint)(8 * i), out var argPtr);
            var arg = ReadString(argPtr,Encoding.UTF8);
#if DEBUG
            Console.WriteLine($"{argPtr:X},{arg}");
#endif
            args.Add(arg);
        }

        return args;
    }

    private string ReadString(nuint ptr, Encoding encoding, int maxLength = 256) {
        this.extMemory.SafeReadRaw(ptr , out var bytes, maxLength);
        var data = encoding.GetString(bytes);
        var eosPos = data.IndexOf('\0');
        return eosPos == -1 ? data : data.Substring(0, eosPos);
    }

    private void GetGameWindowPtr() {
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

            if (instr.Code == Code.Lea_r64_m) {
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
