#pragma once
#include <unordered_map>

#include "Hooks/Hook.h"

class AdvancedHook : public Hook
{
public:

    // Installs the hook, returns true on success.
    bool Install(Injector& injector) override = 0;

    // Uninstalls the hook.
    void Uninstall() override = 0;

    // Gets a descriptive name for what this hook is doing.
    const char* GetName() override = 0;

    // Do polling here
    void Update() override {}

protected:
    static void ProtectedReadBytes(void* readAddr, void* readBuff, int len);
    static void ProtectedWriteBytes(void* destAddr, void* patch, int len);
    
    bool HookMid64(uintptr_t targetInstructionAddress, unsigned char* outOriginalBytes, const int originalInstructionLen, void* newFunc);

private:
    static void ProtectedReadBase(void* dest, void* src, int len);
    static void WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo);

    // Finds and allocates a page near our target address
    static void* TryAllocatePageNearAddress(uintptr_t targetAddr);

    // TODO: Some system that checks if we already have a page allocated nearby our new hooks and reuse the page
    // Map our hooked function pages so we dont duplicate pages when unhook/rehooking
    std::unordered_map<uintptr_t, void*> m_relayPageMap;
};
