#include "LockOnAdjustHook.h"
#include "Injector/Injector/Injector.h"

#include "Shared/Core/Utils/Logging.h"

#include <Windows.h>
#include <cstdint>
#include <cstring>

#include "Injector/ASM/ASMGlobals.h"
#include "ThirdParty/detours/src/detours.h"


void _protectedRead(void* dest, void* src, int len)
{
	DWORD oldProt = 0;
	VirtualProtect(dest, len, PAGE_EXECUTE_READWRITE, &oldProt);
	memcpy(dest, src, len);
	VirtualProtect(dest, len, oldProt, &oldProt);
}

void ProtectedReadBytes(void* readAddr, void* readBuff, int len)
{
	_protectedRead(readBuff, readAddr, len);
}

void ProtectedWriteBytes(void* destAddr, void* patch, int len)
{
	_protectedRead(destAddr, patch, len);
}

void* AllocatePageNearAddress(uintptr_t targetAddr)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

	uint64_t startAddr = (uint64_t(targetAddr) & ~(PAGE_SIZE - 1)); //round down to nearest page boundary
	uint64_t minAddr = std::min(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
	uint64_t maxAddr = std::max(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

	uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

	uint64_t pageOffset = 1;
	while (1)
	{
		uint64_t byteOffset = pageOffset * PAGE_SIZE;
		uint64_t highAddr = startPage + byteOffset;
		uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

		bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

		if (highAddr < maxAddr)
		{
			void* outAddr = VirtualAlloc((void*)highAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr)
				return outAddr;
		}

		if (lowAddr > minAddr)
		{
			void* outAddr = VirtualAlloc((void*)lowAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr != nullptr)
				return outAddr;
		}

		pageOffset++;

		if (needsExit)
		{
			break;
		}
	}

	return nullptr;
}

void WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo)
{
	uint8_t AbsJumpInstructions[] = 
	{ 
		0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov r10, addr
		0x41, 0xFF, 0xE2 //jmp r10
	  };

	const uint64_t AddrToJumpTo64 = (uint64_t)addrToJumpTo;
	memcpy(&AbsJumpInstructions[2], &AddrToJumpTo64, sizeof(AddrToJumpTo64));
	memcpy(absJumpMemory, AbsJumpInstructions, sizeof(AbsJumpInstructions));
}

void HookMid64(uintptr_t targetInstructionAddress, unsigned char* outOriginalBytes, const int originalInstructionLen, void* newFunc)
{
	// Save our instruction we're modifying
	memcpy(outOriginalBytes, (void*)targetInstructionAddress, originalInstructionLen);

	// Create page near target for 5byte jmp
	// Create and write the relay function
	void* RelayFuncMemory = AllocatePageNearAddress(targetInstructionAddress);
	WriteAbsoluteJump64(RelayFuncMemory, newFunc); // write relay func instructions
	
	// Create a jmp instruction to the relay
	uint8_t* Patch = (uint8_t*)malloc(sizeof(uint8_t) * originalInstructionLen);
	const uint64_t RelAddr = (uint64_t)RelayFuncMemory - ((uint64_t)targetInstructionAddress + (sizeof(uint8_t) * 5));
	memset(Patch, 0x90, originalInstructionLen); // No-op the patch
	Patch[0] = 0xE8; // jmp
	memcpy(Patch + 1, &RelAddr, 4); // Relative address for previous jmp

	// Overwrite our target to relative jmp to our relay that AbsJmps to our patch
	ProtectedWriteBytes((void*)targetInstructionAddress, Patch, originalInstructionLen);

	free(Patch);
}

void Unhook64(uintptr_t targetFunctionAddress, char* originalBytes, int len)
{
	ProtectedWriteBytes((void*)targetFunctionAddress, originalBytes, len);
}

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
	S_ASM_BASE_ADDRESS = injector.GetBaseAddress();
	const uintptr_t TargetAddress = injector.GetBaseAddress() + SetLockOnDataOffset;
	HookMid64(TargetAddress, S_OriginalFunctionBytes, S_OriginalFuncLen, &HookWrapper);
	return true;
}

void LockOnAdjustHook::Uninstall()
{
	// TODO: Unhook
}

const char* LockOnAdjustHook::GetName()
{
	return "Lock on adjust";
}
