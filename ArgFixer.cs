using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

using Reloaded.Memory.Buffers;
using Reloaded.Memory.Sources;
using Reloaded.Memory.Utilities;

using Microsoft.Win32;
using System.Reflection.Emit;
using System.Linq.Expressions;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Diagnostics;
//using Reloaded.Memory.Sigscan;
using System.Formats.Asn1;
using Decoder = Iced.Intel.Decoder;
using System.Runtime.Serialization;
using PeNet;
using Microsoft.Win32.SafeHandles;
using static Reloaded.Memory.Buffers.Internal.Kernel32.Kernel32;
namespace FfxivArgLauncher
{
    internal unsafe sealed class ArgFixer
    {
        private readonly Process targetProcess;
        private readonly bool disposeTargetProcess;
        private readonly ExternalMemory extMemory;
        private readonly CircularBuffer circularBuffer;
        private readonly PrivateMemoryBuffer memoryBuffer;
        private nuint MainModuleBaseAddress;
        //private readonly Scanner scanner;

        private nuint stringStartWithFunctionAddr;
        private nuint argFixFunctionAddr;

        public ArgFixer(Process targetProcess, bool disposeTargetProcess = true)
        {
            this.targetProcess = targetProcess;
            this.disposeTargetProcess = disposeTargetProcess;

            this.extMemory = new ExternalMemory(targetProcess);
            this.circularBuffer = new CircularBuffer(4096, this.extMemory);
            this.memoryBuffer = new MemoryBufferHelper(targetProcess).CreatePrivateMemoryBuffer(4096);
        }

        public void Fix() {
            this.GetMainModuleAddress();
            this.SetupArgFixFunction();
            this.SetupHook(this.MainModuleBaseAddress + 0x66850);
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

        public void SetupStringStartWithFunction()
        {
            //int strncmp(const char* s1, const char* s2, register size_t n)
            //{
            //    register unsigned char u1, u2;

            //    while (n-- > 0)
            //    {
            //        u1 = (unsigned char)*s1++;
            //        u2 = (unsigned char)*s2++;
            //        if (u1 != u2)
            //            return u1 - u2;
            //        if (u1 == '\0')
            //            return 0;
            //    }
            //    return 0;
            //}

            var asm = new Assembler(64);
            var return_0 = asm.CreateLabel();
            var return_value = asm.CreateLabel();
            var loop = asm.CreateLabel();

            asm.test(r8, r8);
            asm.jz(return_0);
            asm.sub(rcx, rdx);

            asm.Label(ref loop);
            asm.movzx(eax, __byte_ptr[rcx + rdx]);
            asm.dec(r8);
            asm.movzx(r9d, __byte_ptr[rdx]);
            asm.lea(rdx, __[rdx + 1]);
            asm.cmp(al, r9b);
            asm.jnz(return_value);
            asm.test(al, al);
            asm.jz(return_0);
            asm.test(r8, r8);
            asm.jnz(loop);

            asm.Label(ref return_0);
            asm.xor(eax, eax);
            asm.ret();

            asm.Label(ref return_value);
            asm.sub(eax, r9d);
            asm.ret();

            var bytes = this.Assemble(asm);
            this.stringStartWithFunctionAddr = this.memoryBuffer.Add(bytes);
            Console.WriteLine($"StringStartWithFunctionPtr: 0x{this.stringStartWithFunctionAddr:X}");
            if (this.stringStartWithFunctionAddr == 0)
                throw new Exception("Unable to allocate StringStartWithFunction");
            this.extMemory.ChangePermission(this.stringStartWithFunctionAddr, bytes.Length, Reloaded.Memory.Kernel32.Kernel32.MEM_PROTECTION.PAGE_EXECUTE_READWRITE);

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
            Console.WriteLine($"ArgFixFunctionAddress: 0x{this.argFixFunctionAddr:X}");

            if (this.argFixFunctionAddr == 0)
                throw new Exception("Unable to allocate ArgFixFunction");
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
            Console.WriteLine($"DetourBodyAddress: 0x{detourBodyAddress:X}");
            asm = new Assembler(64);
            asm.mov(rax, detourBodyAddress);
            asm.jmp(rax);
            for (int i = 0; i < bytesNum - 12; i++)
            {
                asm.nop();
            }

            bytes = this.Assemble(asm);
            Console.WriteLine(bytes.Length);
            this.extMemory.WriteRaw(sdoLoginAddr, bytes);
            //Console.WriteLine($"hookAddress: 0x{hookAddress:X}");
            //asm.
        }

        private void GetMainModuleAddress()
        {
            for (var mbi = new MEMORY_BASIC_INFORMATION { };
                VirtualQueryEx(this.targetProcess.Handle, mbi.BaseAddress, out mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
                mbi.BaseAddress = mbi.BaseAddress + mbi.RegionSize)
            {
                byte[] szFileName = new byte[260]; // MAX_PATH
                int dwSize = szFileName.Length;

                int result = GetMappedFileNameA(this.targetProcess.Handle, mbi.BaseAddress, szFileName, dwSize);
                if (result > 0)
                {
                    string fileName = Encoding.UTF8.GetString(szFileName, 0, result);
                    //Console.WriteLine($"Mapped File: {fileName}, Base Address: {mbi.BaseAddress}");
                    if (Path.GetFileName(fileName) == "ffxiv_dx11.exe")
                    {
                        this.MainModuleBaseAddress = (nuint)mbi.BaseAddress;
                        return;
                    }
                }
            }
            throw new Exception("Can not found main module");
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

        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern int GetMappedFileNameA(IntPtr hProcess, IntPtr lpv, [Out] byte[] lpFilename, int nSize);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);
    }
}
