// Dark Souls 3 - Open Server

#pragma once

#include "Server/Service.h"

#include <memory>
#include <vector>
#include <unordered_map>

class Server;
class GameClient;
class NetConnection;
class NetConnectionUDP;
class RSAKeyPair;
class Cipher;

// When the user goes through the authentication service an auth state is created
// in the game service to allow future game sessions. Without an authentication state
// the game service will ignore the clients packets.

struct GameClientAuthenticationState
{
    uint64_t AuthToken;
    std::vector<uint8_t> CwcKey;
    float LastRefreshTime;
};

// The game server is responsible for responding to any requests that game clients make. 
// Its connected to after the user has visited the login server and the authentication server.

class GameService 
    : public Service
{
public:
    GameService(Server* OwningServer, RSAKeyPair* ServerRSAKey);
    virtual ~GameService();

    virtual bool Init() override;
    virtual bool Term() override;
    virtual void Poll() override;

    virtual std::string GetName() override;

    Server* GetServer() { return ServerInstance; }

    void CreateAuthToken(uint64_t AuthToken, const std::vector<uint8_t>& CwcKey);
    void RefreshAuthToken(uint64_t AuthToken);

protected:

    void HandleClientConnection(std::shared_ptr<NetConnection> ClientConnection);

private:
    Server* ServerInstance;

    std::shared_ptr<NetConnectionUDP> Connection;

    std::vector<std::shared_ptr<GameClient>> Clients;

    std::unordered_map<uint64_t, GameClientAuthenticationState> AuthenticationStates;

    RSAKeyPair* ServerRSAKey;

};