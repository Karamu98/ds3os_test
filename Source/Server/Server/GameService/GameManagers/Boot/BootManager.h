/*
 * Dark Souls 3 - Open Server
 * Copyright (C) 2021 Tim Leonard
 *
 * This program is free software; licensed under the MIT license.
 * You should have received a copy of the license along with this program.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

#pragma once

#include "Server/GameService/GameManager.h"

struct Frpg2ReliableUdpMessage;
class Server;

// Handles client requests relating to the boot flow.
// eg. Announcement messages, eula and alike.

class BootManager
    : public GameManager
{
public:    
    BootManager(Server* InServerInstance);

    virtual bool OnMessageRecieved(GameClient* Client, const Frpg2ReliableUdpMessage& Message) override;

    virtual std::string GetName() override;

protected:
    bool Handle_RequestWaitForUserLogin(GameClient* Client, const Frpg2ReliableUdpMessage& Message);
    bool Handle_RequestGetAnnounceMessageList(GameClient* Client, const Frpg2ReliableUdpMessage& Message);

private:
    Server* ServerInstance;

};