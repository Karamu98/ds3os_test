#include "LockOnAdjustHook.h"
#include "Injector/Injector/Injector.h"

#include "Shared/Core/Utils/Logging.h"

#include <Windows.h>
#include <cstdint>

#include "Injector/ASM/ASMGlobals.h"


constexpr uintptr_t SetLockOnDataOffset = 0x8CE7DB;
constexpr int S_OriginalFuncLen = 7;
unsigned char S_OriginalFunctionBytes[S_OriginalFuncLen];

extern "C" void* __fastcall HookAction(void* arg1_rax)
{
	float* LoSTime = (float*)((unsigned char*)arg1_rax + 0x2910);
	const float CurrentLoSTime = *LoSTime;
	*LoSTime = 10.0f;
	Log("Set LockOn LoS Timeout time from: %f to %f", CurrentLoSTime, *LoSTime);

	// Return the address needed for the mov instruction we replaced to use in the wrapper
	void* Dest = S_ASM_BASE_ADDRESS + ((unsigned char*)0x4766CA0);
	return Dest;
}

extern "C" void HookWrapper();


bool LockOnAdjustHook::Install(Injector& injector)
{
	m_targetAddress = injector.GetBaseAddress() + SetLockOnDataOffset;
	TryPlaceHook();

	return true;
}

void LockOnAdjustHook::Uninstall()
{
	if(m_isActive)
	{
		ProtectedWriteBytes((void*)m_targetAddress, S_OriginalFunctionBytes, S_OriginalFuncLen);
		m_isActive = false;
	}
	else
	{
		Warning("Tried to uninstall a hook that wasnt installed")
	}
}

const char* LockOnAdjustHook::GetName()
{
	return "Lock on adjust";
}

void LockOnAdjustHook::Update()
{
	static SHORT LastState;
	const SHORT CurrentKeyState = GetAsyncKeyState(VK_F5);
	if(CurrentKeyState && !LastState)
	{
		// Key pressed
		if(m_isActive)
		{
			Warning("Disabled lock time adjust hook")
			Uninstall();
		}
		else
		{
			Success("Enabled lock time adjust hook")
			TryPlaceHook();
		}
	}

	LastState = CurrentKeyState;
}

void LockOnAdjustHook::TryPlaceHook()
{
	m_isActive = HookMid64(m_targetAddress, S_OriginalFunctionBytes, S_OriginalFuncLen, &HookWrapper);
}
