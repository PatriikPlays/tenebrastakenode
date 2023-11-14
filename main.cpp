#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <openssl/rand.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXUserAgent.h>
#include <nlohmann/json.hpp>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_CONNECTION_TIMEOUT_SECOND 10
#include "httplib.h"

using json = nlohmann::json;

std::string version = "0.1";

size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* response) {
    size_t totalSize = size * nmemb;
    response->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

std::string getWSUrl(std::string syncNode) {    
    httplib::Client cli(syncNode);

    auto res = cli.Post("/ws/start");

    if (res == nullptr) {
        std::cout << "Failed to start WS, no response received" << std::endl;
        throw std::exception();
    }

    if (res->status != 200) {
        std::cout << "Received non 200 response code from WS start: " << res->status << std::endl;
        throw std::exception();
    }

    try {
        json parsedResponse = json::parse(res->body);

        if (parsedResponse["ok"]!=NULL && parsedResponse["url"]!=NULL) {
            return parsedResponse["url"];
        } else {
            std::cout << "WS start response invalid or not ok" << std::endl;
            throw std::exception();
        }
    } catch (json::parse_error& e) {
        std::cout << "WS start response invalid, failed to parse response" << std::endl;
        throw std::exception();
    }
}

std::string getValidator(std::string syncNode) {
    httplib::Client cli(syncNode);

    auto res = cli.Get("/staking/validator");

    if (res == nullptr) {
        std::cout << "Failed to GET validator: no response received" << std::endl;
        throw std::exception();
    }

    if (res->status != 200) {
        std::cout << "Failed to GET validator: Got response code " << res->status << std::endl;
        throw std::exception();
    }

    try {
        json parsedResponse = json::parse(res->body);

        if (parsedResponse["ok"]!=NULL && parsedResponse["validator"]!=NULL) {
            return parsedResponse["validator"];
        } else {
            std::cout << "Validator response invalid or not ok: " << res->body << std::endl;
            throw std::exception();
        }
    } catch (json::parse_error& e) {
        std::cout << "Validator response invalid, failed to parse response: " << res->body << std::endl;
        throw std::exception();
    }
}

std::string genNonce(size_t size) {
    std::string nonce;
    nonce.reserve(size);

    for (int i = 0; i<size; i++)
        nonce = nonce + char(rand() % 26 + 97);

    return nonce;
}

void run(std::string syncNode, std::string privKey, bool debugEnabled) {
    std::cout << "Using " << syncNode << " as tenebra node" << std::endl;

    std::string wsUrl;

    try {
        wsUrl = getWSUrl(syncNode);   
    } catch(std::exception e) {
        return;
    }

    ix::initNetSystem();

    ix::WebSocket webSocket;
    
    webSocket.setUrl(wsUrl);

    uint64_t messageId = 1;
    uint64_t loginMessageId = 0;

    std::time_t lastKeepalive = std::time(0);

    webSocket.setOnMessageCallback([&messageId, privKey, syncNode, &webSocket, &loginMessageId, &lastKeepalive, debugEnabled](const ix::WebSocketMessagePtr& msg)
        {
            if (msg->type == ix::WebSocketMessageType::Message)
            {
                if (debugEnabled) {
                    std::cout << "DEBUG Received message: " << msg->str << std::endl;
                }

                json parsedMsg;
                bool ok = false;
                try {
                    parsedMsg = json::parse((msg->str));
                    ok = true;
                } catch (json::parse_error& e) {
                    std::cout << "Failed to parse WS message " << msg->str << "\n" << e.what() << '\n'
                    << "exception id: " << e.id << '\n'
                    << "byte position of error: " << e.byte << std::endl;
                }

                if (ok) {
                    if (parsedMsg["type"] == "keepalive") {
                        lastKeepalive = std::time(0);
                    } else if (!parsedMsg.contains("ok") || parsedMsg["ok"] == true) {
                        if (parsedMsg["id"] == loginMessageId) {
                            std::string address = parsedMsg["address"]["address"];
                            std::cout << "Logged in as " << address << std::endl;

                            std::string validator = "";
                            try {
                                validator = getValidator(syncNode);   
                            } catch(std::exception e) {
                                std::cout << "Failed to GET latest validator, ignoring" << std::endl;
                            } 

                            if (validator.length() > 0 && validator == address) {
                                std::cout << "Were already the validator, submitting" << std::endl;

                                std::string nonce = genNonce(16);

                                std::cout << "Submitting block with nonce " << nonce << std::endl;

                                json submitBlock = {
                                    {"id", messageId},
                                    {"type", "submit_block"},
                                    {"nonce", nonce}
                                };

                                webSocket.send(submitBlock.dump());
                                messageId++;
                                std::cout << "Submitted block" << std::endl;
                            }
                        } else if (parsedMsg["type"] == "event") {
                            if (parsedMsg["event"] == "block") {
                                std::cout << "Received new block " << parsedMsg["block"]["hash"] << std::endl;
                            } else if (parsedMsg["event"] == "validator") {
                                std::string nonce = genNonce(16);
                                
                                std::cout << "Submitting block with nonce " << nonce << std::endl;

                                json submitBlock = {
                                    {"id", messageId},
                                    {"type", "submit_block"},
                                    {"nonce", nonce}
                                };

                                webSocket.send(submitBlock.dump());
                                messageId++;
                                std::cout << "Submitted block" << std::endl;
                            }
                        }
                    } else {
                        std::cout << "Received non OK message: " << msg->str << std::endl;
                    }
                }
            }
            else if (msg->type == ix::WebSocketMessageType::Open)
            {
                std::cout << "Connection established" << std::endl;
                {
                    json loginMsg = {
                        {"id", messageId},
                        {"type", "login"},
                        {"privatekey", privKey}
                    };

                    webSocket.send(loginMsg.dump());
                    loginMessageId = messageId;
                    messageId++;
                }
                {
                    json subscribeValidatorsMsg = {
                        {"id", messageId},
                        {"type", "subscribe"},
                        {"event", "ownValidators"}
                    };

                    webSocket.send(subscribeValidatorsMsg.dump());
                    messageId++;
                }
                {
                    json subscribeBlocksMsg = {
                        {"id", messageId},
                        {"type", "subscribe"},
                        {"event", "blocks"}
                    };

                    webSocket.send(subscribeBlocksMsg.dump());
                    messageId++;
                }
            }
            else if (msg->type == ix::WebSocketMessageType::Error)
            {
                std::cout << "Connection error: " << msg->errorInfo.reason << std::endl;
                webSocket.close();
                return;
            }
        }
    );

    webSocket.disableAutomaticReconnection();
    webSocket.start();

    while (true) {
        if (difftime(std::time(0), lastKeepalive) >= 30.0) {
            std::cout << "Websocket timed out" << std::endl;
            webSocket.close();
            return;
        }
        sleep(1);
    }
}

std::string trimUrlEndSlashes(const std::string& str) {
    std::string trimmedStr = str;
  
    while (!trimmedStr.empty() && trimmedStr.back() == '/') {
        trimmedStr.erase(trimmedStr.size() - 1);
    }
  
    return trimmedStr;
}

int main() {
    using namespace std::chrono;

    std::cout << "tenebrastakenode v" << version << std::endl;

    char* privKey = getenv("TENEBRA_PKEY");
    std::string syncNode = "https://tenebra.lil.gay";

    bool debug = false;

    if (privKey == NULL) {
        std::cout << "Missing TENEBRA_PKEY env variable" << std::endl;
        exit(1);
    }

    if (getenv("TENEBRA_NODE") != NULL) {
        syncNode = getenv("TENEBRA_NODE");
    }

    const char* debugStr = getenv("DEBUG");

    if (debugStr != nullptr && (std::string(debugStr) == "1" || std::string(debugStr) == "true")) {
        debug = true;
        std::cout << "Running with debug enabled" << std::endl;
    }

    syncNode = trimUrlEndSlashes(syncNode);
    
    uint64_t time_ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    srand((uint32_t)(time_ms % 4294967296));

    while (true) {
        run(syncNode, privKey, debug);
        std::cout << "Exited, restarting in 5 seconds..." << std::endl;
        sleep(5);
    }
    
    return 0;
}