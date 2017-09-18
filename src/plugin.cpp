// OllyHelper.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "weakod.h"
#include "asm.h"

BOOL WINAPI DllMain(HMODULE mod,ULONG reason,LPVOID reserved)
{
	if(reason == DLL_PROCESS_ATTACH)
	{
		g_mod = mod;
	}
	return TRUE;
}

// ODBG2_Pluginquery() is a "must" for valid OllyDbg plugin. It must check
// whether given OllyDbg version is correctly supported, and return 0 if not.
// Then it should fill plugin name and plugin version (as UNICODE strings) and
// return version of expected plugin interface. If OllyDbg decides that this
// plugin is not compatible, it will be unloaded. Plugin name identifies it
// in the Plugins menu. This name is max. 31 alphanumerical UNICODE characters
// or spaces + terminating L'\0' long. To keep life easy for users, name must
// be descriptive and correlate with the name of DLL. Parameter features is
// reserved for the future. I plan that features[0] will contain the number
// of additional entries in features[]. Attention, this function should not
// call any API functions: they may be incompatible with the version of plugin!
int ODBG2_Pluginquery(int ollydbgversion,ulong *features, wchar_t pluginname[SHORTNAME], wchar_t pluginversion[SHORTNAME])
{
	// Check whether OllyDbg has compatible version. This plugin uses only the
	// most basic functions, so this check is done pro forma, just to remind of
	// this option.
	if (ollydbgversion<201) return 0;
	// Report name and version to OllyDbg.
	wcscpy(pluginname, THISPLUGIN_NAME);       // Name of plugin
	wcscpy(pluginversion, THISPLUGIN_VER);       // Version of plugin
	return PLUGIN_VERSION;               // Expected API version
};

static LRESULT WINAPI WeakODMsgProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
	if (msg==WM_USER)
	{
		((void(*)(intptr_t))lp)(wp);
		return 0;
	}
	return DefWindowProc(hw, msg, wp, lp);
}

int ODBG2_Plugininit()
{
	Addtolist( 0, 0, THISPLUGIN_NAME L" v" THISPLUGIN_VER L" by goldenegg@pediy [goldenegg@vip.qq.com]" );
	//create weak msg window.
	TCHAR clsname[32];
	swprintf(clsname, L"wo:%d", GetTickCount());

	WNDCLASS cls = {sizeof(cls)};
	cls.hInstance = GetModuleHandle(0);
	cls.lpfnWndProc = WeakODMsgProc;
	cls.lpszClassName = clsname;
	cls.style = CS_DBLCLKS;
	RegisterClass(&cls);
	HWND hWnd = CreateWindow(clsname, L"", WS_OVERLAPPEDWINDOW, 0, 0, CW_USEDEFAULT, CW_USEDEFAULT, HWND_MESSAGE, 0, GetModuleHandle(0), 0);
	g_hWeakMsg = hWnd;
	return 0;
}

// Function is called when user opens new or restarts current application.
// Plugin should reset internal variables and data structures to the initial
// state.
void ODBG2_Pluginreset(void) {
	g_sDlls.clear();
	TCHAR s0[1024] = {0};
	Stringfromini(THISPLUGIN_NAME, AUTOBREAKDLL, s0, _countof(s0));

	for (wchar_t *s=s0, *s1=s0, *se=s0+wcslen(s0); s1<=se; ++s1)
	{
		if(*s1 == '|' || *s1 == 0)
		{
			*s1 = 0;
			while (*s==' ' || *s=='\t') ++s;
			if (*s)
			{
				g_sDlls.push_back(s);
			}
			s = s1 + 1;
		}
	}
	g_debugee.clean();
};

int MenuFunc(t_table *pt, wchar_t *name, ulong index, int mode);

// Plugin menu that will appear in the main OllyDbg menu. Note that this menu
// must be static and must be kept for the whole duration of the debugging
// session.
static t_menu mainmenu[] = {
	{ L"&Options...", L"Open options dialog", K_NONE, MenuFunc, NULL, 100 },
	{ L"Alloc &Memory", L"alloc memory in debugee.",  K_NONE, MenuFunc, NULL, 101 },
	{ L"&Inject Dll", L"inject a dll",  K_NONE, MenuFunc, NULL, 102 },
	{ L"|About",  L"About " THISPLUGIN_NAME, K_NONE, MenuFunc, NULL, 103 },
	{ NULL, NULL, K_NONE, NULL, NULL, 0 }
};

// Adds items either to main OllyDbg menu (type=PWM_MAIN) or to popup menu in
// one of the standard OllyDbg windows, like PWM_DISASM or PWM_MEMORY. When
// type matches, plugin should return address of menu. When there is no menu of
// given type, it must return NULL. If menu includes single item, it will
// appear directly in menu, otherwise OllyDbg will create a submenu with the
// name of plugin. Therefore, if there is only one item, make its name as
// descriptive as possible.
t_menu * ODBG2_Pluginmenu(wchar_t *type)
{
	if (wcscmp(type,PWM_MAIN)==0)
		return mainmenu;
	return NULL;
};

// OllyDbg calls this optional function once on exit. At this moment, all MDI
// windows created by plugin are already destroyed (and received WM_DESTROY
// messages). Function must free all internally allocated resources, like
// window classes, files, memory etc.
void ODBG2_Plugindestroy()
{
}

#ifdef _UNICODE
#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_IA64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='ia64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
#endif
