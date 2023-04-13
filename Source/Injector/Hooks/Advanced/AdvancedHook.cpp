#include "AdvancedHook.h"

#include <Windows.h>

#include "Core/Utils/Logging.h"
#include "Injector/ASM/ASMGlobals.h"



void AdvancedHook::ProtectedReadBase(void* dest, void* src, int len)
{
	DWORD oldProt = 0;
	VirtualProtect(dest, len, PAGE_EXECUTE_READWRITE, &oldProt);
	memcpy(dest, src, len);
	VirtualProtect(dest, len, oldProt, &oldProt);
}

void AdvancedHook::ProtectedReadBytes(void* readAddr, void* readBuff, int len)
{
	ProtectedReadBase(readBuff, readAddr, len);
}

void AdvancedHook::ProtectedWriteBytes(void* destAddr, void* patch, int len)
{
	ProtectedReadBase(destAddr, patch, len);
}

void* AdvancedHook::TryAllocatePageNearAddress(const uintptr_t targetAddr)
{
	SYSTEM_INFO SysInfo;
	GetSystemInfo(&SysInfo);
	const uint64_t PageSize = SysInfo.dwPageSize;

	const uint64_t StartAddr = (uint64_t(targetAddr) & ~(PageSize - 1)); //round down to nearest page boundary
	const uint64_t MinAddr = std::min(StartAddr - 0x7FFFFF00, (uint64_t)SysInfo.lpMinimumApplicationAddress);
	const uint64_t MaxAddr = std::max(StartAddr + 0x7FFFFF00, (uint64_t)SysInfo.lpMaximumApplicationAddress);

	const uint64_t StartPage = (StartAddr - (StartAddr % PageSize));

	uint64_t PageOffset = 1;
	while (true)
	{
		const uint64_t ByteOffset = PageOffset * PageSize;
		const uint64_t HighAddr = StartPage + ByteOffset;
		const uint64_t LowAddr = (StartPage > ByteOffset) ? StartPage - ByteOffset : 0;

		const bool NeedsExit = HighAddr > MaxAddr && LowAddr < MinAddr;

		if (HighAddr < MaxAddr)
		{
			void* OutAddr = VirtualAlloc((void*)HighAddr, PageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (OutAddr)
			{
				return OutAddr;
			}
		}

		if (LowAddr > MinAddr)
		{
			void* OutAddr = VirtualAlloc((void*)LowAddr, PageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (OutAddr != nullptr)
			{
				return OutAddr;
			}
		}

		PageOffset++;

		if (NeedsExit)
		{
			break;
		}
	}

	return nullptr;
}

void AdvancedHook::WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo)
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

bool AdvancedHook::HookMid64(const uintptr_t targetInstructionAddress, unsigned char* outOriginalBytes, const int originalInstructionLen, void* newFunc)
{
	// Save our instruction we're modifying
	memcpy(outOriginalBytes, (void*)targetInstructionAddress, originalInstructionLen);

	// Create page near target for 5byte jmp
	// Create and write the relay function
	void* RelayFunctionMemory = nullptr;
	const auto Iter = m_relayPageMap.find(targetInstructionAddress);
	if(Iter == m_relayPageMap.end())
	{
		RelayFunctionMemory = TryAllocatePageNearAddress(targetInstructionAddress);
		if(RelayFunctionMemory == nullptr)
		{
			Fatal("Couldnt allocate memory for hook relay")
			return false;
		}
		m_relayPageMap[targetInstructionAddress] = RelayFunctionMemory;
	}
	else
	{
		RelayFunctionMemory = Iter->second;
	}

	// Write/Overwrite relay jump
	WriteAbsoluteJump64(RelayFunctionMemory, newFunc); // write relay func instructions

	// Create a relative jump instruction to the relay
	uint8_t* Patch = (uint8_t*)malloc(sizeof(uint8_t) * originalInstructionLen);
	const uint64_t RelAddr = (uint64_t)RelayFunctionMemory - ((uint64_t)targetInstructionAddress + (sizeof(uint8_t) * 5));
	memset(Patch, 0x90, originalInstructionLen); // No-op the patch
	Patch[0] = 0xE8; // jmp
	memcpy(Patch + 1, &RelAddr, 4); // Relative address for previous jmp

	// Overwrite our targetInstruction to relative jmp to our relay
	ProtectedWriteBytes((void*)targetInstructionAddress, Patch, originalInstructionLen);

	free(Patch);

	return true;
}