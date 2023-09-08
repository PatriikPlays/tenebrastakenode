#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXUserAgent.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

std::string version = "0.1";

size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* response) {
    size_t totalSize = size * nmemb;
    response->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

std::string getWSUrl(std::string syncNode) {
    CURL* curl;
    CURLcode res;
    std::string url = syncNode+"/ws/start";
    long timeoutSeconds = 10;

    std::string ret;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");

        // Set the timeout value in seconds
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeoutSeconds);

        std::string response;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cout << "Failed to POST " << url << ": " << curl_easy_strerror(res) << std::endl;
            throw std::exception();
        } else {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            if (response_code != 200) {
                std::cout << "Failed to POST " << url << ": Got response code " << response_code << std::endl;
                throw std::exception();
            }

            try {
                json parsedResponse = json::parse(response);

                if (parsedResponse["ok"]) {
                    ret = parsedResponse["url"];
                } else {
                    std::cout << "WS start response not ok: " << response << std::endl;
                    throw std::exception();
                }
            } catch (json::parse_error& e) {
                std::cout << "Failed to parse WS start response: " << e.what() << '\n'
                  << "exception id: " << e.id << '\n'
                  << "byte position of error: " << e.byte << std::endl;
                throw std::exception();
            }
        }

        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    return ret;
}

std::string getValidator(std::string syncNode) {
    CURL* curl;
    CURLcode res;
    std::string url = syncNode+"/staking/validator";
    long timeoutSeconds = 10;

    std::string ret;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

        // Set the timeout value in seconds
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeoutSeconds);

        std::string response;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cout << "Failed to GET " << url << ": " << curl_easy_strerror(res) << std::endl;
            throw std::exception();
        } else {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            if (response_code != 200) {
                std::cout << "Failed to GET " << url << ": Got response code " << response_code << std::endl;
                throw std::exception();
            }

            try {
                json parsedResponse = json::parse(response);

                if (parsedResponse["ok"]) {
                    ret = parsedResponse["validator"];
                } else {
                    std::cout << "Validator response not ok: " << response << std::endl;
                    throw std::exception();
                }
            } catch (json::parse_error& e) {
                std::cout << "Failed to parse validator response: " << e.what() << '\n'
                  << "exception id: " << e.id << '\n'
                  << "byte position of error: " << e.byte << std::endl;
                throw std::exception();
            }
        }

        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    return ret;
}

std::string base64_encode(const unsigned char* data, size_t input_length) {
    BIO* bio = nullptr;
    BIO* b64 = nullptr;
    BUF_MEM* bufferPtr = nullptr;
    std::string result;

    // Create a Base64 filter BIO
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    // Disable line breaks in the output
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    // Write the data to the BIO
    BIO_write(bio, data, static_cast<int>(input_length));
    BIO_flush(bio);
    
    // Get the encoded string
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    // Copy the encoded string from the BIO buffer
    result.assign(bufferPtr->data, bufferPtr->length - 1);

    BIO_free_all(bio);

    return result;
}

std::string genNonce() {
    unsigned char* buf = new unsigned char[16];
    while (true) {
        if (RAND_bytes(buf, sizeof(buf)) == 1) {
            break;
        }
    }
    std::string str = base64_encode(buf, sizeof(buf));
    delete[] buf;
    return str;
}

void run(std::string syncNode, std::string privKey) {
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

    webSocket.setOnMessageCallback([&messageId, privKey, syncNode, &webSocket, &loginMessageId, &lastKeepalive](const ix::WebSocketMessagePtr& msg)
        {
            if (msg->type == ix::WebSocketMessageType::Message)
            {
                //std::cout << "received message: " << msg->str << std::endl;

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

                                std::string nonce = genNonce();

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
                                std::string nonce = genNonce();
                                
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
    std::cout << "tenebrastakenode v" << version << std::endl;

    char* privKey = getenv("TENEBRA_PKEY");
    std::string syncNode = "https://tenebra.lil.gay";

    if (privKey == NULL) {
        std::cout << "Missing TENEBRA_PKEY env variable" << std::endl;
        exit(1);
    }

    if (getenv("TENEBRA_NODE") != NULL) {
        syncNode = getenv("TENEBRA_NODE");
    }

    syncNode = trimUrlEndSlashes(syncNode);

    while (true) {
        run(syncNode, privKey);
        std::cout << "Exited, restarting in 5 seconds..." << std::endl;
        sleep(5);
    }
    
    return 0;
}