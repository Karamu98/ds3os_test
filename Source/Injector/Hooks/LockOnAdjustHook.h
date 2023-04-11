#pragma once

#include "Injector/Hooks/Hook.h"

class LockOnAdjustHook : public Hook
{
public:
    virtual bool Install(Injector& injector) override;
    virtual void Uninstall() override;
    virtual const char* GetName() override;

};
