/********************************************************************
	created:	2004-4-15 16:59
	filename: 	d:\mydevelop\mydevelop\DbgHelper\DbgHelper\codeutil.cpp
	file path:	d:\mydevelop\mydevelop\DbgHelper\DbgHelper
	author:		swiftcar
*********************************************************************/

#include "stdafx.h"

#define DECL(TYPE,NAME,X) TYPE * NAME= (TYPE*)(void*)(X);


namespace CODEUTIL
{
	static int memcmp_withmask(LPBYTE dst,LPBYTE src,DWORD srclen,LPBYTE mask)
	{
		for(DWORD x=0;x<srclen;++x)
		{
			BYTE v = dst[x] - src[x];
			if(mask[x] && v!=0)
			{
				return (int)(signed char)(v);
			}
		}
		return 0;
	}

	void * SearchCode(HMODULE mod,LPBYTE code,DWORD codelen,LPBYTE codemask)
	{
		LPBYTE exeInst = (LPBYTE)mod;
		DECL(IMAGE_DOS_HEADER, DosHeader,exeInst);
		DECL(IMAGE_NT_HEADERS, NtHeader, exeInst + DosHeader->e_lfanew);
		DWORD imagesz = NtHeader->OptionalHeader.SizeOfImage;
		if(codemask == 0)
		{
			for(DWORD x=0;x<=imagesz-codelen;++x)
			{
				if(memcmp((LPBYTE)mod+x,code,codelen) == 0)
					return (LPBYTE)mod+x;
			}
		}
		else
		{
			for(DWORD x=0;x<=imagesz-codelen;++x)
			{
				if(memcmp_withmask((LPBYTE)mod+x,code,codelen,codemask) == 0)
					return (LPBYTE)mod+x;
			}
		}
		return 0;
	}
};
