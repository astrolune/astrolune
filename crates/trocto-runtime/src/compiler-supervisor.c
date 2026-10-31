/* Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT */
/* Trusted fixed Windows compiler launcher, built with MSVC and embedded in Rust.
   Contract source is never evaluated by a shell or this bootstrap. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define COMMAND_CAP 32767
#define ARGUMENT_CAP 65536
#define ARGUMENT_COUNT_CAP 128

static int append(wchar_t *output,size_t *position,wchar_t value) {
    if(*position>=COMMAND_CAP-1)return 0;
    output[(*position)++]=value;output[*position]=0;return 1;
}
static int repeat(wchar_t *output,size_t *position,wchar_t value,size_t count) {
    for(size_t index=0;index<count;++index)if(!append(output,position,value))return 0;
    return 1;
}
static int quote(wchar_t *output,size_t *position,const wchar_t *value) {
    size_t slashes=0;
    if(!append(output,position,L'"'))return 0;
    for(;*value;++value) {
        if(*value==L'\\'){++slashes;continue;}
        if(!repeat(output,position,L'\\',*value==L'"'?slashes*2+1:slashes)||!append(output,position,*value))return 0;
        slashes=0;
    }
    return repeat(output,position,L'\\',slashes*2)&&append(output,position,L'"');
}
static int arguments(const wchar_t *path,wchar_t **compiler,wchar_t *command) {
    FILE *input=NULL;
    if(_wfopen_s(&input,path,L"rb")!=0)return 0;
    size_t position=0,count=0;
    int valid=1;
    for(;;) {
        unsigned char header[4];size_t received=fread(header,1,4,input);
        if(!received&&feof(input))break;
        if(received!=4||++count>ARGUMENT_COUNT_CAP){valid=0;break;}
        uint32_t length=(uint32_t)header[0]|((uint32_t)header[1]<<8)|((uint32_t)header[2]<<16)|((uint32_t)header[3]<<24);
        if(length>ARGUMENT_CAP){valid=0;break;}
        char *bytes=(char *)malloc((size_t)length+1);
        wchar_t *wide=(wchar_t *)calloc((size_t)length+1,sizeof(wchar_t));
        if(!bytes||!wide){free(bytes);free(wide);valid=0;break;}
        if(fread(bytes,1,length,input)!=length){free(bytes);free(wide);valid=0;break;}
        bytes[length]=0;
        if(memchr(bytes,0,length)||(length&&!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,bytes,(int)length,wide,(int)length))){free(bytes);free(wide);valid=0;break;}
        free(bytes);
        if(count==1){*compiler=wide;}else if(!append(command,&position,L' ')){free(wide);valid=0;break;}
        if(!quote(command,&position,wide))valid=0;
        if(count!=1)free(wide);
        if(!valid)break;
    }
    fclose(input);return valid&&count&&*compiler&&**compiler;
}
static DWORD supervise(const wchar_t *request) {
    wchar_t *compiler=NULL;
    wchar_t *command=(wchar_t *)calloc(COMMAND_CAP,sizeof(wchar_t));
    DWORD status=125;
    HANDLE job=NULL,stdio[3]={NULL,NULL,NULL};
    LPPROC_THREAD_ATTRIBUTE_LIST attributes=NULL;
    PROCESS_INFORMATION child={0};
    int initialized=0;
    if(!command||!arguments(request,&compiler,command))goto cleanup;
    job=CreateJobObjectW(NULL,NULL);if(!job)goto cleanup;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0};
    limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS|JOB_OBJECT_LIMIT_PROCESS_MEMORY|JOB_OBJECT_LIMIT_JOB_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit=8;
    limits.ProcessMemoryLimit=(SIZE_T)512*1024*1024;
    limits.JobMemoryLimit=(SIZE_T)1024*1024*1024;
    if(!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof limits))goto cleanup;
    const DWORD kinds[3]={STD_INPUT_HANDLE,STD_OUTPUT_HANDLE,STD_ERROR_HANDLE};
    for(unsigned index=0;index<3;++index) {
        HANDLE original=GetStdHandle(kinds[index]);
        if(!original||original==INVALID_HANDLE_VALUE||!DuplicateHandle(GetCurrentProcess(),original,GetCurrentProcess(),&stdio[index],0,TRUE,DUPLICATE_SAME_ACCESS))goto cleanup;
    }
    SIZE_T bytes=0;InitializeProcThreadAttributeList(NULL,2,0,&bytes);
    attributes=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,bytes);
    if(!attributes||!InitializeProcThreadAttributeList(attributes,2,0,&bytes))goto cleanup;
    initialized=1;
    if(!UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,&job,sizeof job,NULL,NULL)
        ||!UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,stdio,sizeof stdio,NULL,NULL))goto cleanup;
    STARTUPINFOEXW startup={0};startup.StartupInfo.cb=sizeof startup;
    startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput=stdio[0];startup.StartupInfo.hStdOutput=stdio[1];startup.StartupInfo.hStdError=stdio[2];startup.lpAttributeList=attributes;
    if(!CreateProcessW(compiler,command,NULL,NULL,TRUE,CREATE_SUSPENDED|CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,NULL,NULL,&startup.StartupInfo,&child))goto cleanup;
    if(ResumeThread(child.hThread)==(DWORD)-1)goto cleanup;
    if(WaitForSingleObject(child.hProcess,INFINITE)!=WAIT_OBJECT_0||!GetExitCodeProcess(child.hProcess,&status))status=125;
cleanup:
    if(status==125)fprintf(stderr,"Trocto compiler supervisor refused (Win32 %lu)\n",GetLastError());
    /* Close the job before publishing completion: descendants cannot keep pipes
       alive after the direct compiler exits or when the parent kills us. */
    if(job)CloseHandle(job);
    if(child.hThread)CloseHandle(child.hThread);if(child.hProcess)CloseHandle(child.hProcess);
    if(initialized)DeleteProcThreadAttributeList(attributes);if(attributes)HeapFree(GetProcessHeap(),0,attributes);
    for(unsigned index=0;index<3;++index)if(stdio[index])CloseHandle(stdio[index]);
    free(compiler);free(command);return status;
}
int wmain(int argc,wchar_t **argv) {
    if(argc!=3)return 125;
    DWORD status=supervise(argv[1]);
    wchar_t pending[COMMAND_CAP];size_t length=wcslen(argv[2]);
    if(length>=COMMAND_CAP-9)return 125;
    memcpy(pending,argv[2],length*sizeof(wchar_t));
    memcpy(pending+length,L".pending",9*sizeof(wchar_t));
    FILE *completion=NULL;
    if(_wfopen_s(&completion,pending,L"wb")!=0)return 125;
    int written=fprintf(completion,"%lu",status);
    if(fclose(completion)!=0||written<1)return 125;
    /* Readers never open a CRT-deny-shared writer or observe a partial status. */
    if(!MoveFileExW(pending,argv[2],MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))return 125;
    return (int)status;
}
