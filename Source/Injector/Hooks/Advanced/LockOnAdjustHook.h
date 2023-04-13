#pragma once

#include "Injector/Hooks/Advanced/AdvancedHook.h"

class LockOnAdjustHook : public AdvancedHook
{
public:
    bool Install(Injector& injector) override;
    void Uninstall() override;
    const char* GetName() override;
    void Update() override;

private:
    void TryPlaceHook();
    
    bool m_isActive = false;
    uintptr_t m_targetAddress = 0;

};
