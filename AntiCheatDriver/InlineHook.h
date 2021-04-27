#pragma once
#include "AntiCheatDriver.h"
#define  _KERNEL_HOOK


#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL_HOOK
#include <minwindef.h>
#else
#include <windows.h>
#endif

    #define  BACKUPCODE_SIZE  0x200


	//////////////////////////////////////////////////////////////////��Ժ�����HOOK Begin////////////////////////////////////////////////////////////////////////////

	typedef  struct  _InlineHookFunctionSt
	{
		PVOID lpHookAddr;   //ԭʼ��hook�ĵ�ַ
		PVOID pNewHookAddr; //��hook�󣬲���ֱ��ʹ��ԭʼ��ַ�������Ҫ����ԭ���ĺ�����Ҫʹ�������ַ
		PVOID lpFakeFuncAddr;   //ɽկ������ַ
		int nOpcodeMove; //��lpHookAddr�㿪ʼ���㣬��Ҫ�ƶ�����ָ�movedOpCode
		BYTE backupCode[BACKUPCODE_SIZE];  //��hook�ָ���ʱ��,������ԭ��ָ��
		BOOL bHookSucc; //ִ���Ƿ�ɹ�
	}InlineHookFunctionSt;


	/*
	    ����˵���� �Ժ������й���hook
	    ����˵����
	        inlineSt�� inline hook�Ľṹ��,ֱ�Ӵ���һ���ṹ���ָ�뼴�ɣ�������ʼ����������������
	        lpHookAddr�� ��hook������ַ
	        lpFakeFuncAddr�� ɽկ������ַ
	*/
	BOOL InitInlineHookFunction(OUT InlineHookFunctionSt* inlineSt, IN PVOID lpHookAddr, IN PVOID lpFakeFuncAddr);



	/*
	    ����˵���� ��װ����hook
	    ����˵����
	    inlineSt�� ֱ�Ӵ���InitInlineHook��ʼ����inlineSt����
	*/
	BOOL InstallInlineHookFunction(IN InlineHookFunctionSt* inlineSt);


	/*
	    ����˵����ж�غ�������hook
	    ����˵����
	    inlineSt�� ֱ�Ӵ���InstallInlineHookʹ�õ�inlineSt����
	*/
	VOID UninstallInlineHookFunction(IN InlineHookFunctionSt* inlineSt);
	//////////////////////////////////////////////////////////////////��Ժ�����HOOK End/////////////////////////////////////////////////////////////////////////////




	//////////////////////////////////////////////////////////////////��ԼĴ�����HOOK Begin///////////////////////////////////////////////////////////////////////
	/*
	    1. hook����ִ�е�ʱ�򣬸����Ĵ����Ļ���������ͨ��ֱ���޸���Щֵ�ԼĴ���������
	    2. ���Ը���esp�Բ������й���
	*/
	typedef struct _HookContex
	{
		ULONG uEflags;
		ULONG uEdi;
		ULONG uEsi;
		ULONG uEbp;
		ULONG uEsp;
		ULONG uEbx;
		ULONG uEdx;
		ULONG uEcx;
		ULONG uEax;
	}HookContex;

	//hook������ָ��������
	typedef void(_stdcall *fpTypeFilterReg)(HookContex* hookContex);
	typedef  struct  _InlineHookRegFilterSt
	{
		PVOID lpHookAddr;   //��hook�ĵ�ַ
		int nOpcodeMove; //��lpHookAddr�㿪ʼ���㣬��Ҫ�ƶ�����ָ�movedOpCode
		BYTE backupCode[BACKUPCODE_SIZE];  //��hook�ָ���ʱ��,������ԭ��ָ��
		//
		BYTE*  hookEntry;   //hook���
		BYTE* movedOpCode; //�ƶ���opcode�Ļ�����
		fpTypeFilterReg lpFilterReg;  //�ԼĴ�������hook�Ļص�����
		BOOL bHookSucc; //hook�Ƿ�ɹ�
	}InlineRegFilterHookSt;


	/*
	����˵���� �ԼĴ������й���hook
	����˵����
		inlineSt�� inline hook�Ľṹ��,ֱ�Ӵ���һ���ṹ���ָ�뼴�ɣ�������ʼ����������������
		lpHookAddr�� �������ַ��ʼ�ĵط�
		lpNewProc�� �µĺ�����ַ
	*/
	BOOL InitRegFilterInlineHook(OUT InlineRegFilterHookSt* inlineSt, IN PVOID lpHookAddr, IN fpTypeFilterReg lpNewProc);




	/*
	����˵���� ��װ�Ĵ�������hook
	����˵����
		inlineSt�� ֱ�Ӵ���InitInlineHook��ʼ����inlineSt����
	*/
	BOOL InstallRegFilterInlineHook(IN InlineRegFilterHookSt* inlineSt);


	/*
	����˵����ж�ؼĴ�������hook
	����˵����
	    inlineSt�� ֱ�Ӵ���InstallInlineHookʹ�õ�inlineSt����
	*/
	VOID UninstallRegFilterInlineHook(IN InlineRegFilterHookSt* inlineSt);

	//////////////////////////////////////////////////////////////////��ԼĴ�����HOOK End/////////////////////////////////////////////////////////////////////



#ifdef __cplusplus
}
#endif





