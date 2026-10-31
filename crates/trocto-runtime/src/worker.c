/* Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT */
/* Trusted framing, platform isolation and quota enforcement. No user C enters this file. */
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef _WIN32
#include <windows.h>
#include <userenv.h>
#include <aclapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fcntl.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <stddef.h>
#include <fcntl.h>
#endif

#ifndef TROCTO_KEYS
#define TROCTO_KEYS 0
#endif
#ifndef TROCTO_LANGUAGE
#define TROCTO_LANGUAGE 1
#endif
#define KEYS_CAP 1024
#define EVENTS_CAP 256
#define WORDS_REQUEST (8 + 8 * KEYS_CAP)
#define WORDS_RESPONSE (4 + 3 * KEYS_CAP + 2 * EVENTS_CAP)
#define MEMORY_LIMIT ((size_t)128 * 1024 * 1024)
#define SANDBOX_CAPS UINT64_C(31)
static int isolation_failure(const char *stage) {
#ifdef _WIN32
    fprintf(stderr,"Trocto isolation %s refused (Win32 %lu)\n",stage,GetLastError());
#else
    fprintf(stderr,"Trocto isolation %s refused (errno %d)\n",stage,errno);
#endif
    return 0;
}

extern int32_t trocto_call(uint64_t, uint64_t, uint64_t *, uint64_t *);
extern int32_t trocto_contract(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t *,uint64_t *,uint64_t *,uint64_t *,uint64_t *,uint64_t *,uint64_t *,uint64_t *,uint64_t *,uint64_t *,uint64_t *);

static uint64_t load(const unsigned char *p) {
    uint64_t value = 0;
    for (unsigned i=0;i<8;++i) value |= (uint64_t)p[i] << (i*8);
    return value;
}
static void store(unsigned char *p,uint64_t value) {
    for (unsigned i=0;i<8;++i) p[i]=(unsigned char)(value>>(i*8));
}

#ifdef _WIN32
static int grant_execute(wchar_t *path,PSID sid,DWORD inherit) {
    PACL old_acl=NULL,new_acl=NULL;
    PSECURITY_DESCRIPTOR descriptor=NULL;
    if (GetNamedSecurityInfoW(path,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,&old_acl,NULL,&descriptor)!=ERROR_SUCCESS) return 0;
    EXPLICIT_ACCESSW rule={0};
    rule.grfAccessPermissions=GENERIC_READ|GENERIC_EXECUTE;
    rule.grfAccessMode=GRANT_ACCESS;
    rule.grfInheritance=inherit;
    rule.Trustee.TrusteeForm=TRUSTEE_IS_SID;
    rule.Trustee.TrusteeType=TRUSTEE_IS_UNKNOWN;
    rule.Trustee.ptstrName=(LPWSTR)sid;
    DWORD result=SetEntriesInAclW(1,&rule,old_acl,&new_acl);
    if (result==ERROR_SUCCESS) result=SetNamedSecurityInfoW(path,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,new_acl,NULL);
    if (new_acl) LocalFree(new_acl);
    if (descriptor) LocalFree(descriptor);
    return result==ERROR_SUCCESS;
}

static int launch_isolated(void) {
    WSADATA launcher_sockets;
    if(WSAStartup(MAKEWORD(2,2),&launcher_sockets)!=0)return 119;
    SOCKET probe_listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    struct sockaddr_in probe_address={0};probe_address.sin_family=AF_INET;probe_address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    int probe_size=sizeof probe_address;
    if(probe_listener==INVALID_SOCKET || bind(probe_listener,(struct sockaddr *)&probe_address,sizeof probe_address)==SOCKET_ERROR || listen(probe_listener,1)==SOCKET_ERROR || getsockname(probe_listener,(struct sockaddr *)&probe_address,&probe_size)==SOCKET_ERROR)return 119;
    SOCKET control=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(control==INVALID_SOCKET || connect(control,(struct sockaddr *)&probe_address,sizeof probe_address)==SOCKET_ERROR)return 119;
    SOCKET accepted=accept(probe_listener,NULL,NULL);if(accepted==INVALID_SOCKET)return 119;
    closesocket(accepted);closesocket(control);
    wchar_t probe_port[16];_snwprintf(probe_port,16,L"%u",ntohs(probe_address.sin_port));
    if(!SetEnvironmentVariableW(L"TROCTO_NETWORK_PROBE_PORT",probe_port))return 119;
    PSID sid=NULL;
    HRESULT profile=CreateAppContainerProfile(L"AstroLune.Trocto.Native.v2",L"Trocto native worker",L"Capability-free Trocto worker",NULL,0,&sid);
    if (FAILED(profile) && profile!=HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) return 120;
    if (!sid && FAILED(DeriveAppContainerSidFromAppContainerName(L"AstroLune.Trocto.Native.v2",&sid))) return 121;
    wchar_t executable[32768],directory[32768],arguments[32768];
    DWORD length=GetModuleFileNameW(NULL,executable,32768);
    if (!length || length>=32768) { FreeSid(sid); return 122; }
    wcscpy(directory,executable);
    wchar_t *separator=wcsrchr(directory,L'\\');
    if (!separator) { FreeSid(sid); return 122; }
    *separator=0;
    if (!grant_execute(directory,sid,0) || !grant_execute(executable,sid,0)) { FreeSid(sid); return 123; }
    HANDLE job=CreateJobObjectW(NULL,NULL);
    if (!job) { FreeSid(sid); return 124; }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0};
    limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS|JOB_OBJECT_LIMIT_PROCESS_MEMORY|JOB_OBJECT_LIMIT_JOB_MEMORY|JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    limits.BasicLimitInformation.ActiveProcessLimit=1;
    limits.ProcessMemoryLimit=MEMORY_LIMIT;
    limits.JobMemoryLimit=MEMORY_LIMIT;
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu={0};
    cpu.ControlFlags=JOB_OBJECT_CPU_RATE_CONTROL_ENABLE|JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    cpu.CpuRate=2000;
    if (!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof limits) || !SetInformationJobObject(job,JobObjectCpuRateControlInformation,&cpu,sizeof cpu)) { CloseHandle(job); FreeSid(sid); return 124; }
    SIZE_T bytes=0;
    InitializeProcThreadAttributeList(NULL,3,0,&bytes);
    LPPROC_THREAD_ATTRIBUTE_LIST attributes=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,bytes);
    if (!attributes || !InitializeProcThreadAttributeList(attributes,3,0,&bytes)) { if(attributes)HeapFree(GetProcessHeap(),0,attributes); CloseHandle(job); FreeSid(sid); return 125; }
    SECURITY_CAPABILITIES security={0};
    security.AppContainerSid=sid;
    HANDLE handles[3]={GetStdHandle(STD_INPUT_HANDLE),GetStdHandle(STD_OUTPUT_HANDLE),GetStdHandle(STD_ERROR_HANDLE)};
    for(unsigned i=0;i<3;++i)if(!SetHandleInformation(handles[i],HANDLE_FLAG_INHERIT,HANDLE_FLAG_INHERIT)){fprintf(stderr,"Trocto handle inheritance %u error %lu\n",i,GetLastError());}
    STARTUPINFOEXW startup={0};
    startup.StartupInfo.cb=sizeof startup;
    startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput=handles[0]; startup.StartupInfo.hStdOutput=handles[1]; startup.StartupInfo.hStdError=handles[2];
    startup.lpAttributeList=attributes;
    int ready=UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,&security,sizeof security,NULL,NULL)
        && UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,handles,sizeof handles,NULL,NULL)
        && UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,&job,sizeof job,NULL,NULL);
    PROCESS_INFORMATION child={0};
    _snwprintf(arguments,32768,L"\"%ls\" --worker",executable);
    if(!ready)fprintf(stderr,"Trocto attributes error %lu\n",GetLastError());
    if (ready) ready=CreateProcessW(executable,arguments,NULL,NULL,TRUE,CREATE_SUSPENDED|CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,NULL,directory,&startup.StartupInfo,&child);
    if(!ready)fprintf(stderr,"Trocto AppContainer CreateProcess/attributes error %lu\n",GetLastError());
    DeleteProcThreadAttributeList(attributes); HeapFree(GetProcessHeap(),0,attributes); FreeSid(sid);
    if (!ready) { CloseHandle(job); return 126; }
    if (ResumeThread(child.hThread)==(DWORD)-1) { TerminateProcess(child.hProcess,127); WaitForSingleObject(child.hProcess,INFINITE); CloseHandle(child.hThread); CloseHandle(child.hProcess); CloseHandle(job); return 127; }
    CloseHandle(child.hThread);
    WaitForSingleObject(child.hProcess,INFINITE);
    DWORD result=128;
    GetExitCodeProcess(child.hProcess,&result);
    CloseHandle(child.hProcess); CloseHandle(job);closesocket(probe_listener);WSACleanup();
    return (int)result;
}

static int establish_isolation(void) {
    HANDLE token=NULL;
    DWORD is_container=0,bytes=0;
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) return isolation_failure("token");
    TOKEN_GROUPS capabilities={0};
    int restricted=GetTokenInformation(token,TokenIsAppContainer,&is_container,sizeof is_container,&bytes) && is_container
        && GetTokenInformation(token,TokenCapabilities,&capabilities,sizeof capabilities,&bytes) && capabilities.GroupCount==0;
    CloseHandle(token);
    BOOL in_job=FALSE;
    if (!restricted || !IsProcessInJob(GetCurrentProcess(),NULL,&in_job) || !in_job) return isolation_failure("restricted-token/job");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0};
    if (!QueryInformationJobObject(NULL,JobObjectExtendedLimitInformation,&limits,sizeof limits,NULL)
        || limits.ProcessMemoryLimit!=MEMORY_LIMIT || limits.BasicLimitInformation.ActiveProcessLimit!=1) return isolation_failure("job quotas");
    /* Real enforcement probes: a normal-user secret, a network socket, a child
       process, and commitment above the configured memory quota must be denied. */
    wchar_t secret[32768];
    DWORD n=GetEnvironmentVariableW(L"TROCTO_SANDBOX_PROBE",secret,32768);
    if (!n || n>=32768) return isolation_failure("probe path");
    for(unsigned mode=0;mode<2;++mode){
        HANDLE file=CreateFileW(secret,mode?GENERIC_WRITE:GENERIC_READ,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
        if (file!=INVALID_HANDLE_VALUE) { CloseHandle(file); return isolation_failure("file allowed"); }
        if (GetLastError()!=ERROR_ACCESS_DENIED) return isolation_failure("file denial code");
    }
    WSADATA sockets;
    int network_denied=0;
    if (WSAStartup(MAKEWORD(2,2),&sockets)!=0) return isolation_failure("winsock init");
    SOCKET socket_handle=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (socket_handle==INVALID_SOCKET) network_denied=WSAGetLastError()==WSAEACCES;
    else {
        wchar_t port[16];if(!GetEnvironmentVariableW(L"TROCTO_NETWORK_PROBE_PORT",port,16)){closesocket(socket_handle);WSACleanup();return isolation_failure("network probe port");}
        struct sockaddr_in address={0}; address.sin_family=AF_INET; address.sin_port=htons((unsigned short)wcstoul(port,NULL,10)); address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        u_long nonblocking=1;
        if(ioctlsocket(socket_handle,FIONBIO,&nonblocking)==SOCKET_ERROR){closesocket(socket_handle);WSACleanup();return isolation_failure("network nonblocking");}
        if (connect(socket_handle,(struct sockaddr *)&address,sizeof address)==SOCKET_ERROR) {
            int error=WSAGetLastError();network_denied=error==WSAEACCES;
            if(error==WSAEWOULDBLOCK){
                fd_set writable,failed;FD_ZERO(&writable);FD_ZERO(&failed);FD_SET(socket_handle,&writable);FD_SET(socket_handle,&failed);
                struct timeval bound={1,0};int result=select(0,NULL,&writable,&failed,&bound);
                /* WFP may drop forbidden lowbox packets instead of returning
                   ACCESS_DENIED. The launcher just connected to this live
                   loopback listener, so a filtered timeout proves denial. */
                if(result==0)network_denied=1;
                else if(result>0 && FD_ISSET(socket_handle,&failed)){int denied=0,size=sizeof denied;if(getsockopt(socket_handle,SOL_SOCKET,SO_ERROR,(char *)&denied,&size)==0)network_denied=denied==WSAEACCES;}
            }
        }
        closesocket(socket_handle);
    }
    WSACleanup();
    if (!network_denied) return isolation_failure("network");
    wchar_t executable[32768],arguments[32768];
    if (!GetModuleFileNameW(NULL,executable,32768)) return 0;
    _snwprintf(arguments,32768,L"\"%ls\" --probe-child",executable);
    STARTUPINFOW startup={0};startup.cb=sizeof startup; PROCESS_INFORMATION child={0};
    if (CreateProcessW(executable,arguments,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&startup,&child)) {
        TerminateProcess(child.hProcess,129); WaitForSingleObject(child.hProcess,INFINITE); CloseHandle(child.hThread); CloseHandle(child.hProcess); return 0;
    }
    void *excess=VirtualAlloc(NULL,MEMORY_LIMIT+32*1024*1024,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (excess) { VirtualFree(excess,0,MEM_RELEASE); return isolation_failure("memory"); }
    return 1;
}
#else
static int limit_resource(int kind,rlim_t value) {
    struct rlimit bound={value,value};
    return setrlimit(kind,&bound)==0;
}
static int establish_isolation(void) {
#if !defined(__x86_64__)
    return 0;
#else
    if (!limit_resource(RLIMIT_AS,MEMORY_LIMIT) || !limit_resource(RLIMIT_STACK,1024*1024)
        || !limit_resource(RLIMIT_CORE,0) || !limit_resource(RLIMIT_CPU,60)
        || !limit_resource(RLIMIT_FSIZE,0) || !limit_resource(RLIMIT_NPROC,0)) return isolation_failure("rlimits");
    void *(*volatile allocate)(size_t)=malloc;
    void *excess=allocate(MEMORY_LIMIT+32*1024*1024);
    if (excess) { free(excess); return isolation_failure("memory"); }
    if (!limit_resource(RLIMIT_NOFILE,3)) return isolation_failure("fd quota");
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_read,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_write,0,5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,1,1,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,2,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_exit,3,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_exit_group,2,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_rt_sigreturn,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog filter={(unsigned short)(sizeof code/sizeof code[0]),code};
    if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0 || prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&filter)!=0) return isolation_failure("seccomp");
    errno=0; if (syscall(SYS_openat,AT_FDCWD,"/etc/passwd",O_RDONLY,0)!=-1 || errno!=EACCES) return isolation_failure("file");
    errno=0; if (syscall(SYS_socket,AF_INET,SOCK_STREAM,0)!=-1 || errno!=EACCES) return isolation_failure("network");
    errno=0; long child=syscall(SYS_fork); if (child==0) _exit(130); if (child!=-1 || errno!=EACCES) return isolation_failure("child");
    return 1;
#endif
}
#endif

int main(int argc,char **argv) {
#ifdef _WIN32
    if (argc==2 && strcmp(argv[1],"--probe-child")==0) return 131;
    if (argc!=2 || strcmp(argv[1],"--worker")!=0) {int result=launch_isolated();if(result)fprintf(stderr,"Trocto launcher exit %d (Win32 %lu)\n",result,GetLastError());return result;}
    if (_setmode(_fileno(stdin),_O_BINARY)==-1 || _setmode(_fileno(stdout),_O_BINARY)==-1) return 132;
#else
    (void)argc;(void)argv;
#endif
    if (setvbuf(stdin,NULL,_IONBF,0)!=0 || setvbuf(stdout,NULL,_IONBF,0)!=0) return 133;
    if (!establish_isolation()) return 134;
    unsigned char readiness[16]; memcpy(readiness,"TCSBX002",8); store(readiness+8,SANDBOX_CAPS);
    if (fwrite(readiness,1,sizeof readiness,stdout)!=sizeof readiness) return 135;
    unsigned char request[WORDS_REQUEST*8],response[WORDS_RESPONSE*8];
    _Alignas(8) uint64_t caller[4],key_words[KEYS_CAP*4],key_lengths[KEYS_CAP],state[KEYS_CAP],present[KEYS_CAP],access[KEYS_CAP],written[KEYS_CAP],events[EVENTS_CAP*2];
    for (;;) {
        size_t n=fread(request,1,sizeof request,stdin);
        if (!n && feof(stdin)) return 0;
        if (n!=sizeof request) return 136;
        uint64_t input=load(request),fuel=load(request+8),height=load(request+16);
        for (unsigned i=0;i<4;++i) caller[i]=load(request+24+i*8);
        uint64_t count=load(request+56);
        if(fuel>UINT64_C(10000000))return 139;
        int32_t status=6;
        memset(response,0,sizeof response); memset(written,0,sizeof written); memset(events,0,sizeof events);
        _Alignas(8) uint64_t value=0,used=0,event_count=0;
        if (count>=TROCTO_KEYS && count<=KEYS_CAP) {
            int valid=1;
            for (unsigned i=0;i<count;++i) {
                const unsigned char *slot=request+64+i*64;
                key_lengths[i]=load(slot);
                for(unsigned word=0;word<4;++word)key_words[i*4+word]=load(slot+8+word*8);
                state[i]=load(slot+40);present[i]=load(slot+48);access[i]=load(slot+56);
                if(key_lengths[i]<1 || key_lengths[i]>256 || present[i]>1 || access[i]>1 || (!present[i]&&state[i]))valid=0;
                if(key_lengths[i]!=32 && (key_words[i*4]|key_words[i*4+1]|key_words[i*4+2]|key_words[i*4+3]))valid=0;
            }
            for(size_t i=64+count*64;i<sizeof request;++i)if(request[i])valid=0;
            if(valid)status=trocto_contract(input,fuel,height,count,key_words,key_lengths,caller,state,present,access,written,events,&event_count,&value,&used);
        }
        store(response,(uint64_t)status);
        if (status==0) {
            if (event_count>EVENTS_CAP) return 137;
            store(response+8,value);store(response+16,used);store(response+24,event_count);
            for (unsigned i=0;i<count;++i) { store(response+32+i*24,state[i]);store(response+40+i*24,present[i]);store(response+48+i*24,written[i]); }
            for (unsigned i=0;i<event_count*2;++i) store(response+32+KEYS_CAP*24+i*8,events[i]);
        }
        if (fwrite(response,1,sizeof response,stdout)!=sizeof response) return 138;
    }
}
