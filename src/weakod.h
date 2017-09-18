#pragma once
#include "resource.h"

#define AUTOBREAKDLL L"AutoBreakDLLs"
#define THISPLUGIN_NAME L"WeakOD"
#define THISPLUGIN_VER  L"1.0.1"

class DebugeeInfo
{
public:
	HANDLE hProcess;
	HANDLE hThread;
	DWORD   pid;
	DWORD   tid;
	void*   Mem;
	void*   dllmem;
	size_t  memsz;
	PVOID   peb;
	bool    gotfirstbp;

	operator bool()
	{
		return hProcess!=0;
	}
	DebugeeInfo()
	{
		clean();
	}
	void clean()
	{
		if(Mem && *this)
		{
			VirtualFreeEx(hProcess, Mem, 0, MEM_RELEASE);
		}
		memset(this, 0, sizeof(*this));
	}
};

extern HMODULE g_mod;
extern HWND    g_hWeakMsg;
extern DebugeeInfo g_debugee;
extern std::vector<wstring> g_sDlls;

class COptDlg
{
public:
	enum {IDD = IDD_OPTIONS};

private:
	HWND m_hWnd;
	DLGPROC m_proc;

protected:
	void CenterWindow()
	{
		RECT rc1={0},rc2={0};
		HWND hParent = GetParent(m_hWnd);
		if (hParent == NULL) hParent = GetDesktopWindow();
		GetWindowRect(hParent,&rc1);
		GetWindowRect(m_hWnd,&rc2);
		int left = (rc1.right - rc1.left - rc2.right + rc2.left) / 2 + rc1.left;
		int top = (rc1.bottom - rc1.top - rc2.bottom + rc2.top)/2 + rc1.top;
		SetWindowPos(m_hWnd,0,left,top,0,0,SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE);
	}
	template <class F>
	intptr_t memfunc_ptr(F func)
	{
		typedef int assert[sizeof(func)==4 ? 1 : -1];
		return *(intptr_t*)&func;
	}
public:
	COptDlg()
	{
		char * mem = (char*)HeapAlloc(GetProcessHeap(), MEM_COMMIT, 24);
		DWORD oldpro;
		VirtualProtect(mem, 24, PAGE_EXECUTE_READWRITE, &oldpro);
		m_proc = (DLGPROC)mem;
		mem[0]         = '\xb9';
		(intptr_t&)mem[1] = (intptr_t)this;
		mem[5]         = '\xe9';
		(intptr_t&)mem[6] = memfunc_ptr(&COptDlg::DlgProc) - (intptr_t)(mem+10);
		m_hWnd = 0;
	}
	~COptDlg()
	{
	}
	DLGPROC getproc()
	{
		return m_proc;
	}

	LRESULT DlgProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp)
	{
		switch (msg)
		{
		case WM_INITDIALOG:
			m_hWnd = hWnd;
			return OnInitDialog();
		case WM_COMMAND:
			{
				WORD code = HIWORD(wp), id=LOWORD(wp);
				HWND hctl = (HWND)lp;
				if (code == BN_CLICKED)
				{
					switch (id)
					{
					case IDOK: return OnOK();
					case IDCANCEL: return OnCancel();
					case IDC_ADD: return OnBnClickedAdd();
					case IDC_REMOVE: return OnBnClickedRemove();
					}
				}
			}
			break;
		default:
			break;
		}
		return FALSE;
	}

	LRESULT OnInitDialog()
	{
		// center the dialog on the screen
		CenterWindow();
		for(size_t i=0;i<g_sDlls.size(); ++i)
		{
			LPCTSTR s = g_sDlls[i].c_str();
			SendDlgItemMessage(m_hWnd, IDC_DLLS, LB_ADDSTRING, 0, (LPARAM)s);
		}
		return TRUE;
	}

	LRESULT OnOK()
	{
		HWND hWnd = GetDlgItem(m_hWnd, IDC_DLLS);
		int nCount = SendMessage(hWnd, LB_GETCOUNT, 0, 0);
		wstring ss,ssAll;
		g_sDlls.clear();
		for(int i=0;i<nCount; ++i)
		{
			int len = SendMessage(hWnd,LB_GETTEXTLEN,i,0);
			if(len <= 0)continue;
			ss.resize(len);
			SendMessage(hWnd,LB_GETTEXT,i,(LPARAM)&ss[0]);
			g_sDlls.push_back(ss);
			ssAll += ss;
			ssAll += L"|";
		}
		if (ssAll.length()>0) ssAll.resize(ssAll.length()-1);
		Writetoini(NULL, THISPLUGIN_NAME, AUTOBREAKDLL, L"%s", ssAll.c_str());
		EndDialog(m_hWnd, IDOK);
		return 0;
	}

	LRESULT OnCancel()
	{
		EndDialog(m_hWnd, IDCANCEL);
		return 0;
	}

	LRESULT OnBnClickedAdd();
	LRESULT OnBnClickedRemove();
};

namespace CODEUTIL
{
	void * SearchCode(HMODULE mod,LPBYTE code,DWORD codelen,LPBYTE codemask);
};

struct InsDLLPar
{
	DWORD eip;
	DWORD loadlib;
	wchar_t dllpath[MAX_PATH];
	char  nopz[16];
	char  executable_code[1024];
};
