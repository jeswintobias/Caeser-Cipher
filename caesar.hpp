#ifndef CAESAR_HPP 
#define CAESAR_HPP  
#include <iostream> 
#include <vector> 
#include <string> 
#include <map> 
#include <tuple> 
#include <regex> 
#include <fstream> 
#include <sstream> 
#include <chrono> 
#include <ctime> 
#include <iomanip> 
#include <random> 
#include <sstream>  
using namespace std;

class CaesarCipher { 
private:     
    vector<int> availableKeys;     
    vector<int> usedKeys;     
    map<string, string> groups; // Public Key -> Group Name     
    map<string, vector<string>> groupMembers; // Public Key -> List of Members     
    map<string, string> groupReferralCodes; // Public Key -> Referral Code     
    map<string, string> groupAdmins; // Public Key -> Admin Username     
    vector<tuple<string, string, string, string,string>> logs; // Logs of messages (username, publicKey, message, privateKey)     
    const string administratorKey = "adminpass"; // Admin password     
    map<string, string> userPrivateKeys; // Store usernames and private keys     
    string loggedInUsername; // Track the current logged-in user     
    string loggedInPrivateKey; // Track the current logged-in private key     
    bool isAdminLoggedInFlag = false; // Flag to indicate if an admin is logged in      
    void initializeAvailableKeys();     
    int generateUniqueKey();     
    string generateReferralCode();     
    int userDefinedRand();     
    string encryptMessage(const string& message) const;     
    string decryptMessage(const string& message) const; 

public:     
    int shift;     
    string privateKey;     
    CaesarCipher(int s, const string& pk);     
    CaesarCipher& operator=(const CaesarCipher& other);     
    void logo_display();     
    bool isValidPrivateKey(const string& username, const string& key);     
    bool login(const string& username, const string& privateKey);     
    bool login(const string& username, const string& privateKey, const string& groupcode);     
    bool isAdmin = false;          

    // Group Management     
    void createGroup(const string& adminUsername);     
    bool enterGroup(const string& publicKey, const string& referralCode, const string& username);     
    void sendGroupMessage(const string& message, const string& publicKey, const string& username,int sendmessage);     
    void displayGroupMessages(const string& publicKey, const string& username);     
    void kickOutMember(const string& publicKey, const string& username);     
    void deleteGroup(const string& key);     
    bool isUserPartOfGroup(const string& publicKey, const string& username);     
    void displayGroupMembers(const string& publicKey);      

    // User and Admin Functions     
    void changeUser();     
    void storePrivateKey(const string& username, const string& key);     
    void setAdmin(bool status);  // Set the login status of the admin     
    bool isUniquePublicKey(const string& publicKey);          

    // Encryption and Decryption     
    string encrypt(const string& message, const string& username, const string& key);     
    string decrypt(const string& message, const string& username, const string& key);      

    // Show Decrypted Messages (admin only)     
    void showDecryptedMessages(const string& publicKey);      

    // Save and Load User Data     
    void saveUserDataToFile();     
    void loadUserDataFromFile(); 
}; 

class Message {
private:
std::string getCurrenttime() {
    auto now = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&currentTime);

    std::ostringstream timeStream;
    timeStream << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");

    return timeStream.str();
}
public:
    std::string content;
    std::string timestamp;
    std::time_t expirationTime;
    Message(const std::string& msgContent, int expirationDurationInHours) {
        content = msgContent;
        timestamp = getCurrenttime();
        expirationTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) + expirationDurationInHours * 60;
    }

    bool isExpired() const {
        return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) > expirationTime;
    }
};

// SecureChatRoom class to handle the core functionalities
class SecureChatRoom {
private:
    std::vector<std::string> users;  
    std::map<std::string, std::pair<std::string, std::string>> userCredentials; 
    std::vector<Message> messageLogs;
    std::map<std::string, std::string> userRoles; 
    const std::string secretCode = "OOPS"; 
    std::map<std::string, std::string> sessionTokens; 
    std::map<std::string, std::time_t> lastActiveTime;

public:
    void registerUser(const std::string& username, const std::string& password, const std::string& role);
    bool loginUser(const std::string& username, const std::string& password);
    bool enterSecureChat(const std::string& enteredCode);
    void sendMessage(const std::string& username, const std::string& message, int expirationDurationInHours);
    void showMessages();
    void displayUserStatus();
    void displayGroupMembers(const std::string& groupName);
    void sendPrivateMessage(const std::string& sender, const std::string& receiver, const std::string& message);

private:
    std::string generateSalt(int length = 16);
    std::string customHashPassword(const std::string& password, const std::string& salt);
    bool verifyPassword(const std::string& enteredPassword, const std::string& storedHash, const std::string& salt);
    std::string encryptMessage(const std::string& sender, const std::string& message);
};

#endif