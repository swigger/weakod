#include "StdAfx.h"
#include "weakod.h"
#include "asm.h"

BOOL GetDLLName(HANDLE hProcess, const LOAD_DLL_DEBUG_INFO & LoadDll, wchar_t *szDllName);

///global variables.
HWND g_hWeakMsg;
std::vector<wstring> g_sDlls;
HMODULE g_mod;
DebugeeInfo g_debugee;

namespace CMDS
{
	void InitAsyncRun()
	{

	}

	BOOL SetPEBDebugFlag(unsigned char v)
	{
		const wchar_t *smsg = v ? L"Set Debug Bit OK!" : L"Clear Debug Bit OK!";
		if(g_debugee)
		{
			//ulong dbgpos = (ulong)g_debugee.peb + 2;
			//Writememory(&v, dbgpos, 1, 0);
			DWORD wtn = 0;
			WriteProcessMemory(g_debugee.hProcess, (char*)g_debugee.peb+2, &v, 1, &wtn); 
			Flash(THISPLUGIN_NAME L" %s", smsg);
			return true;
		}
		return FALSE;
	}

	void AllocMem(size_t sz /* = 12*1024 */, bool forcealloc)
	{
		if(! g_debugee)
		{
			Error(L"nothing to do!");
			return;
		}
		void * mem0 = 0;
		void * & Mem = g_debugee.Mem==0 ? g_debugee.Mem : mem0;

		if (g_debugee.Mem == 0 || forcealloc)
		{
			if (g_debugee.Mem == 0) g_debugee.memsz = sz;
			Mem = VirtualAllocEx(g_debugee.hProcess, 0, sz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if(Mem)
			{
				Listmemory();
				Message((u_long)Mem, L"%#x bytes allocated at address %p!", sz, Mem);
			}
			else
				Error(L"Alloc Failed!");
		}else Error(L"Mem already allocated at %p! See log window.\r\n"
			L"You can goto that address by right click the msg in log window.\r\n"
			L"\r\nPress ctrl key to force allocation.", g_debugee.Mem);
	}

	void InjectDll(void)
	{
		if (!g_debugee)
		{
			Error(L"Nothing to do!");
			return;
		}

		void * & dllmem = g_debugee.dllmem;

		OPENFILENAME ofn = {sizeof(ofn)};       // common dialog box structure
		wchar_t szFile[MAX_PATH] = {0};       // buffer for file name

		// Initialize OPENFILENAME
		ofn.hwndOwner = hwollymain;
		ofn.lpstrFile = szFile;
		ofn.nMaxFile = _countof(szFile);
		ofn.lpstrFilter = L"dll files(*.dll)\0*.dll\0all files(*.*)\0*.*\0";
		ofn.nFilterIndex = 1;
		ofn.lpstrTitle = L"select dll file";
		ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

		wchar_t path[MAX_PATH];
		GetCurrentDirectory(_countof(path),path);
		BOOL b = GetOpenFileName(&ofn);
		SetCurrentDirectory(path);
		if (b)
		{
			if(!dllmem)
			{
				dllmem = VirtualAllocEx(g_debugee.hProcess,0,sizeof(InsDLLPar),MEM_COMMIT,PAGE_EXECUTE_READWRITE);
				Listmemory();
				Message((u_long)dllmem, L"dll memory at %p",dllmem);
			}

			InsDLLPar par;
			DWORD tmp;
			DWORD tid = Getcputhreadid();
			if(tid == 0) tid=g_debugee.tid;
			t_thread * x = Findthread(tid);

			memset(&par,0,sizeof(par));
			memset(par.nopz,0x90,sizeof(par.nopz));
			wcscpy(par.dllpath, szFile);
			memcpy(par.executable_code, GetStart2(), GetSize2());
			par.eip = x->reg.ip;

			HMODULE krnl = GetModuleHandle(L"kernel32");
			par.loadlib = (DWORD)GetProcAddress(krnl,"LoadLibraryW");
			WriteProcessMemory(g_debugee.hProcess, dllmem, &par,sizeof(par),&tmp);

			intptr_t neweip = (intptr_t)dllmem + offsetof(InsDLLPar,executable_code);
			x->context.Eip = neweip;
			x->reg.ip = neweip;
			Registermodifiedbyuser(x);
			Setcpu(tid,neweip, 0, 0, 0, CPU_REDRAW);
		}
	}
}

// Menu function of Disassembler pane that follows existing bookmark.
int MenuFunc(t_table *pt, wchar_t *name, ulong index, int mode)
{
	if (mode == MENU_VERIFY)
	{
		switch (index)
		{
		case 100://optins.
		case 103: //about..
			break;
		case 101: //alloc memory.
		case 102: //inject dll.
			return g_debugee ? MENU_NORMAL : MENU_ABSENT;
			break;
		}
		return MENU_NORMAL;
	}
	if (mode == MENU_EXECUTE)
	{
		switch (index)
		{
		case 100://optins.
			{
				COptDlg dlg;
				DialogBox(g_mod, MAKEINTRESOURCE(COptDlg::IDD), hwollymain, dlg.getproc());
			}
			break;
		case 101: //alloc memory.
			CMDS::AllocMem(12*1024, (GetAsyncKeyState(VK_CONTROL)&0x8000) ? true : false );
			break;
		case 102: //inject dll.
			CMDS::InjectDll();
			break;
		case 103: //about..
			MessageBox(hwollymain, THISPLUGIN_NAME L" v" THISPLUGIN_VER L" by goldenegg@pediy [goldenegg@vip.qq.com]", L"About", MB_ICONINFORMATION);
			break;
		}
	}
    return MENU_ABSENT;
};

LRESULT COptDlg::OnBnClickedAdd()
{
	TCHAR dllname[MAX_PATH];
	GetDlgItemText(m_hWnd, IDC_EDDLLNAME, dllname, _countof(dllname));
	SendDlgItemMessage(m_hWnd, IDC_DLLS, LB_ADDSTRING, 0, (LPARAM)dllname);
	return 0;
}

LRESULT COptDlg::OnBnClickedRemove()
{
	int nSel = SendDlgItemMessage(m_hWnd, IDC_DLLS, LB_GETCURSEL, 0, 0);
	if(nSel >= 0)
	{
		SendDlgItemMessage(m_hWnd, IDC_DLLS, LB_DELETESTRING, nSel, 0);
	}
	return 0;
}

std::map<intptr_t,BYTE> pribps;

static void DoStopAtModule(HMODULE addr,LPCWSTR mname)
{
	IMAGE_DOS_HEADER idh;
	IMAGE_NT_HEADERS inh;

	DWORD readed;
	PBYTE ptr = (PBYTE)addr;
	HANDLE hProcess = g_debugee.hProcess;

	if ( ReadProcessMemory(hProcess,ptr,&idh,sizeof(idh),&readed) && 
		readed == sizeof(idh) && idh.e_magic == IMAGE_DOS_SIGNATURE &&
		ReadProcessMemory(hProcess,ptr + idh.e_lfanew,&inh,sizeof(inh),&readed) &&
		readed == sizeof(inh) && inh.Signature == IMAGE_NT_SIGNATURE &&
		inh.FileHeader.Machine == IMAGE_FILE_MACHINE_I386 &&
		inh.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC &&
		inh.OptionalHeader.AddressOfEntryPoint != 0)
	{
		BYTE int3=0xcc;
		BYTE code;
		DWORD readed;
		ulong baddr = (ulong)ptr + inh.OptionalHeader.AddressOfEntryPoint;

		Removeint3breakpoint(baddr, BP_ONESHOT);
		Flushmemorycache();
		ReadProcessMemory(hProcess,(PVOID)baddr,&code,1,&readed);
		if(code == 0xCC)
		{
			Error(L"found a break point exist at %p,the entry of module %s", baddr, mname);
		}
		//else if (Setint3breakpoint(baddr, BP_MANUAL|BP_TEMP, 0, 0, 0, 0, L"",L"",L"")==0) {}
		else
		{
			DWORD oldProtect;
			pribps[baddr] = code;
			VirtualProtectEx(hProcess,(PVOID)baddr,1,PAGE_EXECUTE_READWRITE,&oldProtect);
			WriteProcessMemory(hProcess,(PVOID)baddr,&int3,1,&readed);
			VirtualProtectEx(hProcess,(PVOID)baddr,1,oldProtect,&oldProtect);
		}
	}
}
static void RemoveBP(intptr_t addr)
{
	Removeint3breakpoint(addr, BP_MANUAL);
}
void ODBG2_Pluginmainloop(DEBUG_EVENT *lpDebugEvent)
{
	if(! lpDebugEvent ) return;

	switch(lpDebugEvent->dwDebugEventCode)
	{
	case OUTPUT_DEBUG_STRING_EVENT:
		break;
	case CREATE_PROCESS_DEBUG_EVENT:
		{
			LPBYTE ppeb;
			DWORD dwRead;
			g_debugee.hProcess = lpDebugEvent->u.CreateProcessInfo.hProcess;
			g_debugee.pid      = lpDebugEvent->dwProcessId;
			g_debugee.hThread  = lpDebugEvent->u.CreateProcessInfo.hThread;
			g_debugee.tid      = lpDebugEvent->dwThreadId;
			ppeb      = (LPBYTE)(lpDebugEvent->u.CreateProcessInfo.lpThreadLocalBase)+0x30;
			ReadProcessMemory(g_debugee.hProcess,ppeb,&g_debugee.peb,4,&dwRead);
			pribps.clear();

			if( GetThreadPriority(GetCurrentThread()) < THREAD_PRIORITY_ABOVE_NORMAL )
			{
				SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_ABOVE_NORMAL);
				Sleep(1);
			}
		}
		break;
	case EXIT_PROCESS_DEBUG_EVENT:
		g_debugee.clean();
		break;
	case EXCEPTION_DEBUG_EVENT:
		//when we first receive this message,set the bit.
		if(lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
		{
			if(!g_debugee.gotfirstbp)
			{
				g_debugee.gotfirstbp = TRUE;
				CMDS::SetPEBDebugFlag(0);
			}
			else
			{
				ulong addr = (ulong)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress;
				std :: map<intptr_t,BYTE>::iterator p = pribps.find(addr);
				DWORD wtn;
				if(p != pribps.end() )
				{
					//if there is a break point, remove it.
					Removeint3breakpoint(addr, BP_ONESHOT);
					Flushmemorycache();

					BYTE code = p->second;
					WriteProcessMemory(g_debugee.hProcess, (PVOID)addr, &code, 1, &wtn);
					Listmemory();
					Setint3breakpoint(addr, BP_MANUAL|BP_BREAK, 0,0,0,0,0,0,0);
					Flushmemorycache();
					pribps.erase(p);
					PostMessage(g_hWeakMsg, WM_USER, addr, (LPARAM) RemoveBP);
				}
			}
		}
		break;
	case LOAD_DLL_DEBUG_EVENT:
		if(lpDebugEvent->u.LoadDll.lpImageName)
		{
			wchar_t fn[MAX_PATH*2];
			LOAD_DLL_DEBUG_INFO & ldll = lpDebugEvent->u.LoadDll;

			if( GetDLLName(g_debugee.hProcess,ldll,fn) )
			{
				wchar_t * ps = wcsrchr(fn, '\\');
				ps ? ++ps : ps = fn;
				_wcslwr(ps);
				for(size_t i=0;i<g_sDlls.size(); ++i)
				{
					wstring s2 = g_sDlls[i];
					_wcslwr(&s2[0]);
					if (wcsstr(ps,s2.c_str()))
					{
						DoStopAtModule((HMODULE)ldll.lpBaseOfDll, ps);
					}
				}
			}
			else
			{
				//_ASSERTE(0 && "getdllname failed.");
			}
		}
		break;
	default:
		break;
	}
}
