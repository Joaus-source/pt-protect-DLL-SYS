#pragma once
#include "AntiCheatDriver.h"

//��Ϣ�ṹ��

typedef struct __AntiCheatMsgQue
{
	KSPIN_LOCK spinMsgQue;
	MsgNode root;
	MsgNode* fist; //��һ��ָ���λ��
	MsgNode* last; //���һ��ָ���λ��
}AntiCheatMsgQue;

//��ʼ���������
VOID InitMsgQue(AntiCheatMsgQue *pMsgQue);
//�������
VOID InsertMsgQue(AntiCheatMsgQue *pMsgQue, MsgNode *node);
//������
MsgNode* PopMsgQue(AntiCheatMsgQue *pMsgQue);
//�ж��Ƿ�Ϊ��
BOOLEAN IsMsgQueEmpty(AntiCheatMsgQue *pMsgQue);
//������������
VOID CleanMsgQue(AntiCheatMsgQue *pMsgQue);

//����һ��MsgNode�Ľڵ�
MsgNode* MakeMsgNode(int nMsgNo);


//֪ͨ��Ϸ�˳�
VOID ExitGame(int nExitGame);