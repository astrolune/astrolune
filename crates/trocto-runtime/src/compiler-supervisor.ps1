# Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT
# Trusted Windows job bootstrap. No contract source is evaluated by PowerShell.
param([Parameter(Mandatory=$true)][string]$Request)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
public static class TroctoCompilerSupervisor {
    [StructLayout(LayoutKind.Sequential)] struct BasicLimits {
        public long ProcessTime, JobTime;
        public uint Flags;
        public UIntPtr MinWorking, MaxWorking;
        public uint ActiveProcesses;
        public UIntPtr Affinity;
        public uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters {
        public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
    }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits {
        public BasicLimits Basic;
        public IoCounters Io;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Startup {
        public int Size;
        public string Reserved, Desktop, Title;
        public uint X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
        public ushort Show, ReservedBytes;
        public IntPtr ReservedPointer, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupEx {public Startup Startup;public IntPtr Attributes;}
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo {public IntPtr Process,Thread;public uint ProcessId,ThreadId;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr security,string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref ExtendedLimits data,uint bytes);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref IntPtr size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder arguments,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string directory,ref StartupEx startup,out ProcessInfo process);
    [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int kind);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle,uint mask,uint flags);
    [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    static string Quote(string value) {
        var output=new StringBuilder("\"");int slashes=0;
        foreach(char c in value) {
            if(c=='\\'){slashes++;continue;}
            output.Append('\\',c=='"'?slashes*2+1:slashes);output.Append(c);slashes=0;
        }
        output.Append('\\',slashes*2);output.Append('"');return output.ToString();
    }
    static string ReadString(BinaryReader input) {
        int count=input.ReadInt32();if(count<0||count>65536)throw new IOException("invalid compiler argument length");
        byte[] bytes=input.ReadBytes(count);if(bytes.Length!=count)throw new IOException("truncated compiler argument");
        return new UTF8Encoding(false,true).GetString(bytes);
    }
    public static int Run(string request) {
        string compiler;var command=new StringBuilder();
        using(var input=new BinaryReader(File.OpenRead(request))) {
            compiler=ReadString(input);command.Append(Quote(compiler));
            while(input.BaseStream.Position<input.BaseStream.Length){command.Append(' ');command.Append(Quote(ReadString(input)));}
        }
        IntPtr job=CreateJobObject(IntPtr.Zero,null),attributes=IntPtr.Zero,jobValue=IntPtr.Zero;
        ProcessInfo child=new ProcessInfo();bool initialized=false;
        if(job==IntPtr.Zero)throw new System.ComponentModel.Win32Exception();
        try {
            var limits=new ExtendedLimits();limits.Basic.Flags=0x2000|0x8|0x100|0x200;limits.Basic.ActiveProcesses=8;
            limits.ProcessMemory=new UIntPtr(512UL*1024*1024);limits.JobMemory=new UIntPtr(1024UL*1024*1024);
            if(!SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(ExtendedLimits))))throw new System.ComponentModel.Win32Exception();
            IntPtr bytes=IntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref bytes);
            attributes=Marshal.AllocHGlobal(bytes);if(!InitializeProcThreadAttributeList(attributes,1,0,ref bytes))throw new System.ComponentModel.Win32Exception();initialized=true;
            jobValue=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(jobValue,job);
            if(!UpdateProcThreadAttribute(attributes,0,new IntPtr(0x2000D),jobValue,new IntPtr(IntPtr.Size),IntPtr.Zero,IntPtr.Zero))throw new System.ComponentModel.Win32Exception();
            var startup=new StartupEx();startup.Startup.Size=Marshal.SizeOf(typeof(StartupEx));startup.Startup.Flags=0x100;
            startup.Startup.Input=GetStdHandle(-10);startup.Startup.Output=GetStdHandle(-11);startup.Startup.Error=GetStdHandle(-12);startup.Attributes=attributes;
            foreach(IntPtr handle in new[]{startup.Startup.Input,startup.Startup.Output,startup.Startup.Error})if(!SetHandleInformation(handle,1,1))throw new System.ComponentModel.Win32Exception();
            if(!CreateProcess(compiler,command,IntPtr.Zero,IntPtr.Zero,true,0x4|0x80000|0x8000000,IntPtr.Zero,Environment.CurrentDirectory,ref startup,out child))throw new System.ComponentModel.Win32Exception();
            if(ResumeThread(child.Thread)==UInt32.MaxValue)throw new System.ComponentModel.Win32Exception();
            if(WaitForSingleObject(child.Process,UInt32.MaxValue)!=0)throw new System.ComponentModel.Win32Exception();
            uint status;if(!GetExitCodeProcess(child.Process,out status))throw new System.ComponentModel.Win32Exception();return unchecked((int)status);
        } finally {
            // Closing this handle kills every remaining descendant, even when
            // the direct compiler exited before an inherited pipe was closed.
            CloseHandle(job);
            if(child.Thread!=IntPtr.Zero)CloseHandle(child.Thread);if(child.Process!=IntPtr.Zero)CloseHandle(child.Process);
            if(initialized)DeleteProcThreadAttributeList(attributes);if(attributes!=IntPtr.Zero)Marshal.FreeHGlobal(attributes);if(jobValue!=IntPtr.Zero)Marshal.FreeHGlobal(jobValue);
        }
    }
}
'@
exit ([TroctoCompilerSupervisor]::Run($Request))
