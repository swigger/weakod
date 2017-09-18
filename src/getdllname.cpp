#include "StdAfx.h"
#include <Psapi.h>

typedef enum _FILE_INFORMATION_CLASS
{
	FileNameInformation = 9, // 9 Y N F
	FileAlternateNameInformation = 21, // 21 Y N F
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _FILE_NAME_INFORMATION { // Information Classes 9 and 21
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID    Pointer;
  };
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

		extern "C" __declspec(dllimport) LONG WINAPI ZwQueryInformationFile(IN HANDLE FileHandle,OUT PIO_STATUS_BLOCK pIoStatusBlock,
			OUT PVOID FileInformation,IN ULONG FileInformationLength,
			IN FILE_INFORMATION_CLASS FileInformationClass);


static BOOL CheckFile(wchar_t * szDllName,HANDLE filehandle)
{
	BY_HANDLE_FILE_INFORMATION fi1,fi2;
	wchar_t dllname[MAX_PATH+4] , *pf , dllname1[MAX_PATH+4];

	if( wcsncmp(szDllName, L"\\\\?\\",4)==0 || wcsncmp(szDllName, L"\\\\.\\", 4) == 0 )
	{
		memmove(szDllName+4, szDllName, (wcslen(szDllName)-4+1)*sizeof(szDllName[0]));
	}

	if(szDllName[1] != ':')
	{
		wcscpy(dllname, szDllName);
		for(pf=dllname;*pf;++pf)
		{
			if(*pf == '/') *pf = '\\';
		}

		//first: tryfind.
		pf = wcsrchr(dllname, '\\');
		if (pf) ++pf; else pf = dllname;
		if (SearchPath(NULL, pf, NULL, MAX_PATH+4, dllname1, &pf) && CheckFile(dllname1,filehandle))
		{
			wcscpy(szDllName, dllname1);
			return TRUE;
		}

		//second: try dosdevice;
		if( _wcsnicmp(L"\\device" , dllname , 7 ) == 0 )
		{
			DWORD drives = GetLogicalDrives();
			wchar_t x[4] = L"C:";
			int len;

			for(int i=0;i<26;++i)
			{
				if( drives & (1<<i) )
				{
					x[0] = 'A' + i;
					if( QueryDosDevice(x,dllname1,_countof(dllname1)) && 
						_wcsnicmp(dllname, dllname1, len = wcslen(dllname1)) == 0 )
					{
						wcscpy(dllname1, x);
						wcscpy(dllname1+2, dllname+len);
						if( CheckFile(dllname1, filehandle) )
						{
							wcscpy(szDllName, dllname1);
							return TRUE;
						}
						else break;
					}
				}
			}
		}

		//third. try it!
		{
			DWORD drives = GetLogicalDrives();
			dllname1[0] = 'A';
			dllname1[1] = ':';
			wcscpy(dllname1+2, dllname);

			for(int i=0;i<26;++i)
			{
				if( drives & (1<<i) )
				{
					dllname1[0] = 'A' + i;
					if( CheckFile(dllname1,filehandle) )
					{
						wcscpy(szDllName, dllname1);
						return TRUE;
					}
				}
			}
		}

		return FALSE;
	}

	if(filehandle == INVALID_HANDLE_VALUE || !filehandle) return TRUE;

	HANDLE hfile = CreateFile(szDllName,0,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		NULL,OPEN_EXISTING,0,NULL);
	if( hfile != INVALID_HANDLE_VALUE && GetFileInformationByHandle(filehandle,&fi1) &&
		GetFileInformationByHandle(hfile,&fi2) && 
		fi1.dwVolumeSerialNumber == fi2.dwVolumeSerialNumber &&
		fi1.nFileIndexHigh == fi2.nFileIndexHigh &&
		fi1.nFileIndexLow == fi2.nFileIndexLow)
	{
		CloseHandle(hfile);
		return TRUE;
	}
	CloseHandle(hfile);
	return FALSE;
}

BOOL GetDLLName(HANDLE hProcess, const LOAD_DLL_DEBUG_INFO & LoadDll, wchar_t *szDllName)
{
	DWORD dwRead = 0;
	PVOID pDll = 0;
	memset(szDllName, 0, sizeof(szDllName[0])*MAX_PATH);

	// 没有文件名信息
	if(LoadDll.lpImageName == NULL && LoadDll.hFile == NULL)
	{
		//_ASSERTE("both imagename and hfile are NULL");
	}

	if (LoadDll.lpImageName)
	{
		// 读取目标进程的内容
		ReadProcessMemory(hProcess, LoadDll.lpImageName, &pDll, sizeof(PVOID), &dwRead);

		if (pDll)
		{
			dwRead = 0;
			wchar_t buf [MAX_PATH*2] = {0};
			intptr_t sz1 = (intptr_t)pDll;
			sz1 = ( (sz1 + 4095) & ~4095 ) - sz1;
			if (sz1 > sizeof(buf)) sz1 = sizeof(buf);

			if ( ReadProcessMemory(hProcess,pDll,buf,sizeof(buf),&dwRead) || 
				ReadProcessMemory(hProcess,pDll,buf,sz1,&dwRead) )
			{
				if (LoadDll.fUnicode)
				{
					wcscpy(szDllName, buf);
				}
				else
				{
					MultiByteToWideChar(CP_ACP, 0, (char*)buf, dwRead, szDllName, MAX_PATH);
				}
				if (CheckFile(szDllName,LoadDll.hFile))
				{
					return TRUE;
				}
			}
		}
	}

	//try to use **
	{
		if (GetModuleFileNameEx(hProcess,(HMODULE)LoadDll.lpBaseOfDll,szDllName,MAX_PATH) &&
			CheckFile(szDllName,LoadDll.hFile) )
			return TRUE;
		if(GetMappedFileName(hProcess,(HMODULE)LoadDll.lpBaseOfDll,szDllName,MAX_PATH) && 
			CheckFile(szDllName,LoadDll.hFile))
			return TRUE;
	}

	if (LoadDll.hFile)
	{
		IO_STATUS_BLOCK x1;
		union
		{
			FILE_NAME_INFORMATION fn;
			char buf[2048];
		};
		memset(buf,0,sizeof(buf));

		if (ZwQueryInformationFile(LoadDll.hFile, &x1, &fn, sizeof(buf), FileNameInformation) >= 0)
		{
			wcscpy(szDllName, fn.FileName);
			if(CheckFile(szDllName,LoadDll.hFile)) return TRUE;
		}
	}

	//ok ,finally,try to read it from the export table.
	{
		IMAGE_DOS_HEADER idh;
		IMAGE_NT_HEADERS ntheader;
		IMAGE_EXPORT_DIRECTORY ied;
		DWORD expva;
		BYTE dllname_tmp[MAX_PATH] = {0};

		if ( ReadProcessMemory(hProcess,LoadDll.lpBaseOfDll,&idh,sizeof(idh),&dwRead) &&
			idh.e_magic == IMAGE_DOS_SIGNATURE && 
			ReadProcessMemory(hProcess,(PBYTE)LoadDll.lpBaseOfDll + idh.e_lfanew,&ntheader,sizeof(ntheader),&dwRead) &&
			(expva = ntheader.OptionalHeader.DataDirectory[0].VirtualAddress) != 0 &&
			ReadProcessMemory(hProcess,(PBYTE)LoadDll.lpBaseOfDll + expva,&ied,sizeof(ied),&dwRead) &&
			ied.Name != 0 &&
			ReadProcessMemory(hProcess,(PBYTE)LoadDll.lpBaseOfDll+ied.Name,dllname_tmp,MAX_PATH,&dwRead) )
		{
			MultiByteToWideChar(CP_ACP, 0, (char*)dllname_tmp, -1, szDllName, MAX_PATH);
			if (CheckFile(szDllName, LoadDll.hFile) )
				return TRUE;
		}
	}

	return FALSE;
}
