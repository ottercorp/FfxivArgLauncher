namespace FfxivArgLauncher;

using Iced.Intel;
using Reloaded.Memory.Buffers;
using Reloaded.Memory.Sigscan;
using Reloaded.Memory.Sources;
using Reloaded.Memory.Utilities;
using Serilog;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using static Iced.Intel.AssemblerRegisters;
using Decoder = Iced.Intel.Decoder;

public unsafe sealed class ArgFixer
{
    private readonly Process targetProcess;
    private readonly bool disposeTargetProcess;
    private readonly ExternalMemory extMemory;
    private readonly PrivateMemoryBuffer memoryBuffer;
    private readonly Scanner scanner;

    private nuint mainModuleBaseAddress;
    private nint mainModuleRegionSize;
    private nuint argFixFunctionAddr;

    public ArgFixer(Process targetProcess, bool disposeTargetProcess = true)
    {
        this.targetProcess = targetProcess;
        this.disposeTargetProcess = disposeTargetProcess;
        Console.WriteLine(targetProcess.Id);

        this.extMemory = new ExternalMemory(targetProcess);
        this.memoryBuffer = new MemoryBufferHelper(targetProcess).CreatePrivateMemoryBuffer(4096);
        this.GetMainModuleAddress();
        this.extMemory.ReadRaw(this.mainModuleBaseAddress, out var exeData, (int)this.mainModuleRegionSize);
        this.scanner = new Scanner(exeData);
    }

    public void Fix()
    {
        this.SetupArgFixFunction();
        var sig = "E8 ?? ?? ?? ?? 44 38 64 24";
        var addr = this.scanner.FindPattern(sig);
        if (!addr.Found)
        {
            throw new Exception($"Can not find address for sdologin:{sig}");
        }

        var callAddr = this.mainModuleBaseAddress + (nuint)addr.Offset;
        this.extMemory.Read<int>(callAddr + 1, out var funcOffset);
        var funcAddr = callAddr + (nuint)funcOffset + 5;
        Log.Verbose($"Found sdoLogin Address:{funcAddr:X} ({callAddr:X} + {funcOffset:X} + 5)");
        this.SetupHook(funcAddr);
    }

    private byte[] Assemble(Assembler assembler, ulong rip = 0)
    {
        using var stream = new MemoryStream();
        assembler.Assemble(new StreamCodeWriter(stream), rip);

        stream.Position = 0;
        var reader = new StreamCodeReader(stream);

        int next;
        var bytes = new byte[stream.Length];
        while ((next = reader.ReadByte()) >= 0)
        {
            bytes[stream.Position - 1] = (byte)next;
        }

        return bytes;
    }

    public void SetupArgFixFunction()
    {
        var strTestId = "DEV.TestSID=";
        var strSndaId = "XL.SndaId=";

        var strTestIdAddress = this.memoryBuffer.Add(Encoding.ASCII.GetBytes(strTestId + '\0'));
        var strSndaIdAddress = this.memoryBuffer.Add(Encoding.ASCII.GetBytes(strSndaId + '\0'));

        //var stringStartWithFunctionPtr = this.memoryBuffer.Add(ref stringStartWithFunctionAddr);
        var asm = new Assembler(64);
        var exit = asm.CreateLabel();
        var testId = asm.CreateLabel();
        var sndaId = asm.CreateLabel();
        var loop = asm.CreateLabel();
        var incr = asm.CreateLabel();

        var strncmp = asm.CreateLabel();

        asm.mov(__[rsp + 0x8], rbx);
        asm.mov(__[rsp + 0x10], rbx);
        asm.push(rdi);
        asm.sub(rsp, 0x20);
        asm.xor(esi, esi);
        asm.mov(__qword_ptr[rcx + 0x61], 1);
        asm.mov(__[rcx + 0x88], rsi);
        asm.mov(rdi, rcx);
        asm.mov(rbx, __[rcx + 8]);
        asm.cmp(__[rcx], esi);
        asm.jle(exit);

        asm.Label(ref testId);
        asm.mov(rcx, __[rbx]);
        asm.lea(rdx, __[strTestIdAddress]);
        asm.mov(r8d, strTestId.Length);
        asm.call(strncmp);
        asm.test(eax, eax);
        asm.jnz(sndaId);
        asm.mov(rax, __[rbx]);
        asm.add(rax, strTestId.Length);
        asm.mov(__[rdi + 0xA0], rax);
        asm.jmp(loop);

        asm.Label(ref sndaId);
        asm.mov(rcx, __[rbx]);
        asm.lea(rdx, __qword_ptr[strSndaIdAddress]);
        asm.mov(r8d, strSndaId.Length);
        asm.call(strncmp);
        asm.test(eax, eax);
        asm.jnz(loop);
        asm.mov(rax, __[rbx]);
        asm.add(rax, strSndaId.Length);
        asm.mov(__[rdi + 0xA8], rax);

        asm.Label(ref loop);
        asm.inc(esi);
        asm.add(rbx, 8);
        asm.cmp(esi, __[rdi]);
        asm.jl(testId);

        asm.Label(ref exit);
        asm.mov(rbx, __[rsp + 0x28 + 8]);
        asm.xor(eax, eax);
        asm.mov(rsi, __[rsp + 0x28 + 0x10]);
        asm.add(rsp, 0x20);
        asm.pop(rdi);
        asm.ret();

        var return_0 = asm.CreateLabel();
        var return_value = asm.CreateLabel();
        //var loop = asm.CreateLabel();

        asm.Label(ref strncmp);
        asm.test(r8, r8);
        asm.jz(return_0);
        asm.sub(rcx, rdx);

        //asm.Label(ref loop);
        asm.AnonymousLabel();
        asm.movzx(eax, __byte_ptr[rcx + rdx]);
        asm.dec(r8);
        asm.movzx(r9d, __byte_ptr[rdx]);
        asm.lea(rdx, __[rdx + 1]);
        asm.cmp(al, r9b);
        asm.jnz(return_value);
        asm.test(al, al);
        asm.jz(return_0);
        asm.test(r8, r8);
        asm.jnz(asm.@B);

        asm.Label(ref return_0);
        asm.xor(eax, eax);
        asm.ret();

        asm.Label(ref return_value);
        asm.sub(eax, r9d);
        asm.ret();


        var bytes = this.Assemble(asm);
        this.argFixFunctionAddr = this.memoryBuffer.Add(bytes);
        Log.Information($"ArgFixFunctionAddress: 0x{this.argFixFunctionAddr:X}");

        if (this.argFixFunctionAddr == 0)
        {
            throw new Exception("Unable to allocate ArgFixFunction");
        }

        this.extMemory.ChangePermission(this.argFixFunctionAddr, bytes.Length, Reloaded.Memory.Kernel32.Kernel32.MEM_PROTECTION.PAGE_EXECUTE_READWRITE);
    }


    public void SetupHook(nuint sdoLoginAddr)
    {
        this.extMemory.ReadRaw(sdoLoginAddr, out var orginBytes, 40);
        var codeReader = new ByteArrayCodeReader(orginBytes);
        var decoder = Decoder.Create(64, codeReader);
        decoder.IP = sdoLoginAddr;

        var bytesNum = 0;
        while (decoder.IP < decoder.IP + (nuint)orginBytes.Length)
        {
            var instr = decoder.Decode();
            if (instr.Code == Code.INVALID)
            {
                break;
            }

            if ((instr.IP - sdoLoginAddr) >= 12)
            {
                bytesNum = (int)(instr.IP - sdoLoginAddr);
                break;
            }
        }

        var asm = new Assembler(64);
        asm.push(rbx);
        asm.push(rdi);
        asm.mov(rax, this.argFixFunctionAddr);
        asm.call(rax);
        asm.pop(rdi);
        asm.pop(rbx);
        asm.ret();

        var bytes = this.Assemble(asm);
        //bytes.Append(bytes);
        var detourBodyAddress = this.memoryBuffer.Add(bytes);
        Log.Information($"DetourBodyAddress: 0x{detourBodyAddress:X}");
        asm = new Assembler(64);
        asm.mov(rax, detourBodyAddress);
        asm.jmp(rax);
        for (int i = 0; i < bytesNum - 12; i++)
        {
            asm.nop();
        }

        bytes = this.Assemble(asm);
        //Console.WriteLine(bytes.Length);
        this.extMemory.WriteRaw(sdoLoginAddr, bytes);
        //Console.WriteLine($"hookAddress: 0x{hookAddress:X}");
        //asm.
    }

    private void GetMainModuleAddress()
    {
        this.mainModuleRegionSize = 0;
        for (var mbi = new MEMORY_BASIC_INFORMATION { };
            VirtualQueryEx(this.targetProcess.Handle, mbi.BaseAddress, out mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
            mbi.BaseAddress = mbi.BaseAddress + mbi.RegionSize)
        {
            var lpFilename = new StringBuilder(1024);
            int result = GetMappedFileNameW(this.targetProcess.Handle, mbi.BaseAddress, lpFilename, lpFilename.Capacity);
            if (result > 0)
            {
                string fileName = lpFilename.ToString();
                Log.Verbose($"Mapped File: {fileName}, Base Address: {mbi.BaseAddress:X}, AllocationBase Address: {mbi.AllocationBase:X},Size: {mbi.RegionSize}");
                if (Path.GetFileName(fileName) == "ffxiv_dx11.exe")
                {
                    this.mainModuleBaseAddress = (nuint)mbi.AllocationBase;
                    this.mainModuleRegionSize += mbi.RegionSize;
                }
            }
        }

        if (this.mainModuleBaseAddress == 0)
        {
            throw new Exception("Can not found main module");
        }

        Log.Verbose($"AllocationBase Address: {this.mainModuleBaseAddress:X},Size: {this.mainModuleRegionSize}");
    }


    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int GetMappedFileNameW(IntPtr hProcess, IntPtr lpv, StringBuilder lpFilename, int nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);
}
