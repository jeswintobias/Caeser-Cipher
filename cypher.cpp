#include "caesar.hpp"
#include <string>

CaesarCipher::CaesarCipher(int s, const std::string& pk)
    : shift(s), privateKey(pk), loggedInUsername(""), loggedInPrivateKey("") {
    initializeAvailableKeys();
}


void CaesarCipher::initializeAvailableKeys() {
    // Initialize available keys (for example, 1 to 1000)
    for (int i = 1; i <= 1000; ++i) {
        availableKeys.push_back(i);
    }
}


int CaesarCipher::userDefinedRand() {
    static std::vector<int> usedKeys;  // To ensure uniqueness
    int key;
    bool keyExists;

    // Loop until we find a unique key
    do {
        key = rand() % 1000 + 1;  // Random number between 1 and 1000
        
        // Check if the key is already in the usedKeys vector
        keyExists = false;
        for (int usedKey : usedKeys) {
            if (usedKey == key) {
                keyExists = true;
                break;
            }
        }
        
        // If keyExists is true, continue the loop, else generate a new key
    } while (keyExists);
    
    usedKeys.push_back(key); 
    return key;
}


std::string CaesarCipher::generateReferralCode() {
    return std::to_string(userDefinedRand() % 1000 + 1);  // Random code between 1 and 1000
}


bool CaesarCipher::login(const std::string& username, const std::string& privateKey) {
    auto it = userPrivateKeys.find(username);
    if (it != userPrivateKeys.end() && it->second == privateKey) {
        loggedInUsername = username;
        loggedInPrivateKey = privateKey;
        return true;
    }
    return false;
}


bool CaesarCipher::login(const std::string& username, const std::string& privateKey, const std::string& groupCode) {
    auto it = userPrivateKeys.find(username);
    if (it != userPrivateKeys.end() && it->second == privateKey) {
        loggedInUsername = username;
        loggedInPrivateKey = privateKey;

        if (!groupCode.empty()) {
            if (enterGroup(groupCode, username,groupCode)) {
                std::cout << "Successfully joined the group!" << std::endl;
            } else {
                std::cout << "Failed to join the group, invalid group code!" << std::endl;
            }
        }
        return true;
    }
    return false;
}


bool isStrongPassword(const std::string& password) {
    int digitCount = 0;
    int charCount = 0;
    int specialCount = 0;

    // Check each character in the password
    for (char ch : password) {
        if (isdigit(ch)) {
            ++digitCount;
        } else if (isalpha(ch)) {
            ++charCount;
        } else if (ispunct(ch)) {
            ++specialCount;
        }
    }

    // Return true if password meets the criteria
    return (digitCount >= 4 && charCount >= 2 && specialCount >= 1);
}


bool CaesarCipher::isValidPrivateKey(const std::string& username, const std::string& key) {
    if (isStrongPassword(key)) {
        userPrivateKeys[username] = key;
        return true;
    } else {
        std::cout << "Weak password. Your password must contain:\n";
        std::cout << "- At least 4 digits\n";
        std::cout << "- At least 2 alphabetic characters\n";
        std::cout << "- At least 1 special character\n";
        return false;  // Exit the program if the password is weak
    }
}


std::string CaesarCipher::encryptMessage(const std::string& message) const {
    std::string encrypted = message;
    for (char& c : encrypted) {
        if (isalpha(c)) {
            char offset = islower(c) ? 'a' : 'A';
            c = (c - offset + shift) % 26 + offset;
        }
    }
    return encrypted;
}


CaesarCipher& CaesarCipher::operator=(const CaesarCipher& other) {
    if (this == &other) {
        return *this;
    }
    this->shift = other.shift;
    this->privateKey = other.privateKey;
    this->availableKeys = other.availableKeys;
    this->userPrivateKeys = other.userPrivateKeys;

    return *this;
}


std::string CaesarCipher::encrypt(const std::string& message, const std::string& username, const std::string& key) {
    std::string encryptedMessage = message;

    for (char& c : encryptedMessage) {
        if (isalpha(c)) { 
            char base = islower(c) ? 'a' : 'A'; 
            c = (c - base + shift) % 26 + base; 
        }
    }
    
    return encryptedMessage;
}


std::string CaesarCipher::decryptMessage(const std::string& message) const {
    std::string decrypted = message;
    for (char& c : decrypted) {
        if (isalpha(c)) {
            char offset = islower(c) ? 'a' : 'A';
            c = (c - offset - shift + 26) % 26 + offset;
        }
    }
    return decrypted;
}


std::string CaesarCipher::decrypt(const std::string& message, const std::string& username, const std::string& key) {
    std::string decryptedMessage = message;
    
    for (char& c : decryptedMessage) {
        if (isalpha(c)) { 
            char base = islower(c) ? 'a' : 'A'; 
            c = (c - base - shift + 26) % 26 + base; 
        }
    }
    
    return decryptedMessage;
}


#include <sstream>
// Function to generate a random salt
void SecureChatRoom::registerUser(const std::string& username, const std::string& password, const std::string& role) {
    if (userRoles.find(username) != userRoles.end()) {
        std::cout << "User already exists!" << std::endl;
        return;
    }

    if (role != "Admin" && role != "Standard") {
        std::cout << "Invalid role. Only 'Admin' and 'Standard' are allowed." << std::endl;
        return;
    }

    std::string salt = generateSalt();
    std::string hashedPassword = customHashPassword(password, salt);
    userCredentials[username] = {hashedPassword, salt};
    userRoles[username] = role;
    users.push_back(username);

    std::cout << "User " << username << " registered successfully as " << role << "." << std::endl;
}

bool SecureChatRoom::loginUser(const std::string& username, const std::string& password) {
    if (userCredentials.find(username) == userCredentials.end()) {
        std::cout << "Invalid username." << std::endl;
        return false;
    }

    std::string storedHash = userCredentials[username].first;
    std::string salt = userCredentials[username].second;

    if (verifyPassword(password, storedHash, salt)) {
        std::string sessionToken = generateSalt(16);
        sessionTokens[username] = sessionToken;
        lastActiveTime[username] = std::time(nullptr);
        std::cout << "Login successful. Welcome, " << username << "!" << std::endl;
        return true;
    } else {
        std::cout << "Invalid password." << std::endl;
        return false;
    }
}

bool SecureChatRoom::enterSecureChat(const std::string& enteredCode) {
    if (enteredCode == secretCode) {
        std::cout << "Access granted. Welcome to the Secure Chat Room!" << std::endl;
        return true;
    } else {
        std::cout << "Access denied. Incorrect secret code." << std::endl;
        return false;
    }
}

void SecureChatRoom::sendMessage(const std::string& username, const std::string& message, int expirationDurationInHours) {
    if (userRoles.find(username) == userRoles.end()) {
        std::cout << "User not found!" << std::endl;
        return;
    }

    if (sessionTokens.find(username) == sessionTokens.end()) {
        std::cout << "User not authenticated. Please login first." << std::endl;
        return;
    }

    Message newMessage(message, expirationDurationInHours);
    messageLogs.push_back(newMessage);
    std::cout << "Message sent by " << username << " at " << newMessage.timestamp << std::endl;
}

void SecureChatRoom::showMessages() {
    for (auto& msg : messageLogs) {
        if (!msg.isExpired()) {
            std::cout << "Message: " << msg.content << " | Sent at: " << msg.timestamp << std::endl;
        } else {
            std::cout << "Message expired. It was sent at: " << msg.timestamp << std::endl;
        }
    }
}

void SecureChatRoom::displayUserStatus() {
    std::cout << "User Status:\n";
    string dummy  = generateSalt(5);
    for (const auto& user : users) {
        // Check if the user is an admin
        std::string displayName = user;

        if (userRoles[user] == "Admin") {
            // Admin can see real name, which can be stored in a separate map or just be the username for now
            displayName = dummy;
        }
        
        std::time_t now = std::time(nullptr);
        double secondsSinceActive = std::difftime(now, lastActiveTime[user]);

        std::string status = secondsSinceActive < 300 ? "Online" : "Offline"; 
        std::cout << displayName << " - " << status << " (Last Active: " << std::ctime(&lastActiveTime[user]) << ")" << std::endl;
    }
}

void SecureChatRoom::displayGroupMembers(const std::string& groupName) {
    std::cout << "Group Members for " << groupName << ": " << std::endl;
    string dummy  = generateSalt(groupName.size());
    int count =  1;
    for (const auto& user : users) {
        std::string displayName = user ;
        count++;
        if (userRoles[user] == "Admin") {
            displayName = dummy;
        }

        std::cout << "- " << displayName << std::endl;
    }
}

void SecureChatRoom::sendPrivateMessage(const std::string& sender, const std::string& receiver, const std::string& message) {
    if (userRoles.find(sender) == userRoles.end() || userRoles.find(receiver) == userRoles.end()) {
        std::cout << "Both users must exist." << std::endl;
        return;
    }

    std::string encryptedMessage = encryptMessage(sender, message);
    std::cout << "Private message from " << sender << " to " << receiver << ": " << encryptedMessage << std::endl;
}

std::string SecureChatRoom::generateSalt(int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string salt;
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distrib(0, sizeof(charset) - 2);

    for (int i = 0; i < length; ++i) {
        salt += charset[distrib(generator)];
    }

    return salt;
}

std::string SecureChatRoom::customHashPassword(const std::string& password, const std::string& salt) {
    std::string hashedPassword;
    std::string combined = password + salt;
    int shiftAmount = salt.length();

    for (char c : combined) {
        hashedPassword += (c + shiftAmount); 
    }

    return hashedPassword;
}

bool SecureChatRoom::verifyPassword(const std::string& enteredPassword, const std::string& storedHash, const std::string& salt) {
    std::string enteredHash = customHashPassword(enteredPassword, salt);
    return enteredHash == storedHash;
}

std::string SecureChatRoom::encryptMessage(const std::string& sender, const std::string& message) {
    std::string encryptionKey = generateSalt(); 
    std::string encryptedMessage = message;

    for (char& c : encryptedMessage) {
        c += encryptionKey.length();
    }

    return encryptedMessage;
}

void CaesarCipher::createGroup(const std::string& adminUsername) {
    std::string publicKey = std::to_string(generateUniqueKey());
    while (!isUniquePublicKey(publicKey)) {
        publicKey = std::to_string(generateUniqueKey());
    }

    std::string referralCode = generateReferralCode();
    groups[publicKey] = adminUsername;  // Assign group admin
    groupReferralCodes[publicKey] = referralCode;  // Store referral code
    groupAdmins[publicKey] = adminUsername;  // Assign admin username
    groupMembers[publicKey].push_back(adminUsername);  // Add admin to group members

    std::cout << "Group created with public key: " << publicKey << " and referral code: " << referralCode << std::endl;
}


bool CaesarCipher::isUniquePublicKey(const std::string& publicKey) {
    return groups.find(publicKey) == groups.end();  // Check if public key is already taken
}


bool CaesarCipher::enterGroup(const std::string& publicKey, const std::string& username, const std::string& referralCode) {
    // Check if the group exists
    if (groups.find(publicKey) == groups.end()) {
        std::cout << "Group with public key " << publicKey << " does not exist!" << std::endl;
        return false;
    }

    // Debugging output for checking referral code
    std::cout << "Expected referral code: " << groupReferralCodes[publicKey] << ", Provided code: " << referralCode << std::endl;

    // Check if the referral code matches
    try {
        if (groupReferralCodes.at(publicKey) != referralCode) {
            std::cout << "Invalid referral code!" << std::endl;
            return false;
        }
    } catch (const std::out_of_range&) {
        std::cout << "Referral code for public key " << publicKey << " not found." << std::endl;
        return false;
    }

    // Check if the user is already a member of the group
    auto& groupMemberList = groupMembers[publicKey];
    if (std::find(groupMemberList.begin(), groupMemberList.end(), username) != groupMemberList.end()) {
        std::cout << "User already a member of the group." << std::endl;
        return false;
    }

    // Add user to the group
    groupMemberList.push_back(username);
    std::cout << "User " << username << " has been added to the group!" << std::endl;
    return true;
}


bool CaesarCipher::isUserPartOfGroup(const std::string& publicKey, const std::string& username) {
    return std::find(groupMembers[publicKey].begin(), groupMembers[publicKey].end(), username) != groupMembers[publicKey].end();
}


int CaesarCipher::generateUniqueKey() {
    if (availableKeys.empty()) {
        initializeAvailableKeys();  // If no available keys, reinitialize
    }
    int key = availableKeys.back();
    availableKeys.pop_back();
    return key;
}


void CaesarCipher::sendGroupMessage(const std::string& message, const std::string& publicKey, const std::string& username,int expirationDurationInHours) {
    // Ensure user is part of the group
    if (!isUserPartOfGroup(publicKey, username)) {
        std::cout << "You are not part of this group. Message cannot be sent." << std::endl;
        return;
    }

    Message newMessage(message, expirationDurationInHours);
    std::string encryptedMessage = encryptMessage(newMessage.content);
    logs.push_back(std::make_tuple(username, publicKey, encryptedMessage, loggedInPrivateKey,newMessage.timestamp));
    
    std::cout << "Message sent successfully at " << newMessage.timestamp << ".\n";
}


void CaesarCipher::displayGroupMembers(const std::string& publicKey) {
    // Check if the group exists
    if (groupMembers.find(publicKey) != groupMembers.end()) {
        const auto& members = groupMembers[publicKey];  // Get the list of members for the specified public key
        std::cout << "(Public Key: " << publicKey << "):" << std::endl;
        std::cout << "(Group members): " << std::endl;

        // Display each member's username
        for (const auto& member : members) {
            std::cout << "- " << member;

            // Check for the latest non-expired message from this member
            bool foundMessage = false;

            for (const auto& log : logs) {
                if (std::get<1>(log) == publicKey && std::get<0>(log) == member) {
                    std::string encryptedMessage = std::get<2>(log);
                    std::string timestamp = std::get<3>(log);

                    // Decrypt the message
                    std::string decryptedMessage = decryptMessage(encryptedMessage);

                    // Check expiration
                    Message msg(decryptedMessage, 2);
                    msg.timestamp = timestamp;

                    if (!msg.isExpired()) {
                        std::cout << " (Latest message: \"" << decryptedMessage << "\" at " << msg.timestamp << ")";
                        foundMessage = true;
                        break;  // Display only the latest message
                    }
                }
            }

            if (!foundMessage) {
                std::cout << " (No non-expired messages)";
            }

            std::cout << std::endl;
        }
    } else {
        std::cout << "Group with Public Key " << publicKey << " does not exist or has no members." << std::endl;
    }
}


void CaesarCipher::displayGroupMessages(const std::string& publicKey, const std::string& username) {
    // Check if the user is part of the group
    auto groupIt = groupMembers.find(publicKey);
    if (groupIt == groupMembers.end() || std::find(groupIt->second.begin(), groupIt->second.end(), username) == groupIt->second.end()) {
        std::cout << "Error: You are not part of this group and cannot view messages." << std::endl;
        return;
    }

    bool messagesFound = false;

    // Loop through the logs and display messages
    for (const auto& log : logs) {
        if (std::get<1>(log) == publicKey) {
            std::string sender = std::get<0>(log);
            std::string encryptedMessage = std::get<2>(log);
            std::string timestamp = std::get<3>(log);

            // Decrypt the message
            std::string decryptedMessage = decryptMessage(encryptedMessage);

            // Check expiration
            Message msg(decryptedMessage, 2);
            msg.timestamp = timestamp;

            if (!msg.isExpired()) {
                std::cout << "[" << sender << "] at " << timestamp << " : " << decryptedMessage << std::endl;
            } else {
                std::cout << "Message from [" << sender << "] at " << timestamp << " has expired.\n";
            }

            messagesFound = true;
        }
    }

    if (!messagesFound) {
        std::cout << "No messages found for the group with public key: " << publicKey << "." << std::endl;
    }
}



void CaesarCipher::deleteGroup(const std::string& publicKey) {
    // Ensure the group exists before trying to delete
    if (groups.find(publicKey) != groups.end()) {
        // Remove group and restore public key to available keys
        availableKeys.push_back(std::stoi(publicKey));  // Add the public key back to available keys
        std::cout << "Group " << publicKey << " deleted and public key restored to available keys." << std::endl;
        groups.erase(publicKey);  // Erase the group from the map
        groupReferralCodes.erase(publicKey);
        groupAdmins.erase(publicKey);
        groupMembers.erase(publicKey);
    } else {
        std::cout << "Group not found!" << std::endl;
    }
}


void CaesarCipher::kickOutMember(const std::string& publicKey, const std::string& username) {
    auto& members = groupMembers[publicKey];
    members.erase(std::remove(members.begin(), members.end(), username), members.end());
}


void CaesarCipher::changeUser() {
    std::string username, privateKey, groupPublicKey;
    
    // Prompt for new username and private key
    std::cout << "Enter new username: ";
    std::cin >> username;
    std::cout << "Enter private key: ";
    std::cin >> privateKey;

    // Validate the private key
    if (!isValidPrivateKey(username, privateKey)) {
        std::cout << "Invalid private key. Must contain at least 4 digits, 2 letters, and 1 special character.\n";
        return;  // Exit if the private key is invalid
    }

    // Attempt login with new credentials
    if (login(username, privateKey)) {
        std::cout << "Login successful as " << username << ".\n";

        // Prompt to join an existing group
        std::cout << "Do you want to join an existing group? (y/n): ";
        char joinGroupChoice;
        std::cin >> joinGroupChoice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // Clear any remaining input

        if (joinGroupChoice == 'y' || joinGroupChoice == 'Y') {
            std::cout << "Enter the public key of the group: ";
            std::cin >> groupPublicKey;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // Clear input buffer

            // Attempt to enter the group with the provided public key
            if (enterGroup(groupPublicKey, username, groupPublicKey)) {
                std::cout << "Successfully joined the group!\n";
            } else {
                std::cout << "Failed to join the group. Invalid group code or you are not invited.\n";
            }
        }
        storePrivateKey(username, privateKey);
    } else {
        std::cout << "Login failed. Invalid username or private key.\n";
    }
}


void CaesarCipher::saveUserDataToFile() {
    std::ofstream file("user_data.txt");
    if (file.is_open()) {
        for (const auto& user : userPrivateKeys) {
            file << user.first << "," << user.second << "\n";
        }
        file.close();
    } else {
        std::cerr << "Error opening file for saving user data.\n";
    }
}

void CaesarCipher::loadUserDataFromFile() {
    std::ifstream file("user_data.txt");
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            size_t pos = line.find(',');
            if (pos != std::string::npos) {
                std::string username = line.substr(0, pos);
                std::string privateKey = line.substr(pos + 1);
                if (!username.empty() && !privateKey.empty()) {
                    userPrivateKeys[username] = privateKey;
                } else {
                    std::cerr << "Malformed data in file: " << line << "\n";
                }
            } else {
                std::cerr << "Invalid line format in file: " << line << "\n";
            }
        }
        file.close();
    } else {
        std::cerr << "Error opening file for loading user data.\n";
    }
}



void CaesarCipher::storePrivateKey(const std::string& username, const std::string& key) {
    userPrivateKeys[username] = key;
}


void CaesarCipher::setAdmin(bool isAdmin) {
    this->isAdmin = isAdmin;  // Assuming you have an `isAdmin` member variable to track admin status
}


void CaesarCipher::showDecryptedMessages(const std::string& publicKey) {
    // Admin-only feature to display decrypted messages
    for (const auto& log : logs) {
        if (std::get<1>(log) == publicKey) {
            // Get the encrypted message from the log tuple
            std::string encryptedMessage = std::get<2>(log);
            
            // Decrypt the message
            std::string decryptedMessage = decryptMessage(encryptedMessage);

            // Display the decrypted message along with the username
            std::cout << "[" << std::get<0>(log) << "] : " << decryptedMessage << std::endl;
        }
    }
}