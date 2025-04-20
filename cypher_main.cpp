#include <iostream>
#include <string>
#include <map>
#include <vector>                                               //SECRET CODE: OOPS
                                                                //ADMIN PASSWORD: adminpass
#include <algorithm>
#include "caesar.hpp"
using namespace std;

int main() {
    SecureChatRoom chatRoom;
    string username, password, role;
    string enteredCode;
    int shift, choice;
    string privateKey, groupMessage, publicKey, referralCode, adminPassword;
    bool check = false;
    CaesarCipher caesar(0, ""); 
    caesar.logo_display();
    cout << "Enter the shift value for Caesar Cipher: ";
    cin >> shift;
    cin.ignore(); 

    cout << "Enter your username: ";
    getline(cin, username);

    cout << "Enter your private key: ";
    getline(cin, privateKey);

    if (!caesar.isValidPrivateKey(username, privateKey)) {
        cout << "Invalid private key. Must contain at least 4 digits, 2 letters, and 1 special character.\n";
        return 1;
    }

    caesar = CaesarCipher(shift, privateKey); 
    caesar.storePrivateKey(username, privateKey);
    cout << "\nLET US BEGIN! <*_*>" << endl;

    // Login feature
    if (!caesar.login(username, privateKey)) {
        return 1; 
    }

    // Start the menu loop
    while (true) {
        cout << "\nMenu:\n";
        cout << "1. Encrypt Message\n";
        cout << "2. Decrypt Message\n";
        cout << "3. Create Group\n";
        cout << "4. Enter Group\n";
        cout << "5. Send Group Message\n";
        cout << "6. Display Group Messages\n";
        cout << "7. Display Decrypted Messages (Admin Only)\n";
        cout << "8. Delete Logs by Private Key (Admin Only)\n";
        cout << "9. Kick Out Member (Admin Only)\n";
        cout << "10. Delete Group (Admin Only)\n";
        cout << "11. Change User\n";
        cout << "12. Register for new user (secure chat)\n";
        cout << "13. Login (secure chat)\n";
        cout << "14. Send private message (secure chat)\n";
        cout << "15. Exit\n";
        cout << "\n--> Choose an option: ";
        
        cin >> choice;
        cin.ignore();  // To clear the input buffer
        
        if (choice < 1 || choice > 15) {
            cout << "Invalid choice. Please enter a number between 1 and 15.\n";
            continue; 
        }
        switch (choice) {
            case 1: {
                string message;
                cout << "Enter message to encrypt: ";
                getline(cin, message);
                string encryptedMessage = caesar.encrypt(message, username, privateKey);
                cout << "Encrypted Message: " << encryptedMessage << endl;
                break;
            }
            case 2: {
                string message;
                cout << "Enter message to decrypt: ";
                getline(cin, message);
                string decryptedMessage = caesar.decrypt(message, username, privateKey);
                cout << "Decrypted Message: " << decryptedMessage << endl;
                break;
            }
            case 3: { // Create group
                cout << "Enter the username: ";
                getline(cin, username);
                caesar.createGroup(username);
                cout << "Group created successfully.\n";
                break;
            }
            case 4: { // Enter group
                cout << "Do you want to use Normal chat or secure chat(only to privileged users)? (N/S): ";
                char choice;
                cin >> choice;
                cin.ignore(); // Clean up the input buffer after reading the character
                
                if ((choice == 'S' || choice == 's') && check) {
                    cout << "Enter the secret code to access secure chat: ";
                    getline(cin, enteredCode);
                    chatRoom.enterSecureChat(enteredCode);
                }
                else{

                    cout << "Enter the public key of the group: ";
                    getline(cin, publicKey);
                    cout << "Enter the referral code: ";
                    getline(cin, referralCode);

                    if (caesar.enterGroup(publicKey, username, referralCode)) {
                        cout << "You have successfully joined the group.\n";
                    } else {
                        cout << "Failed to join the group. Check public key and referral code.\n";
                    }
                }
                break;
            }
            case 5: { // Send group message
                if(check)
                {
                    std::string message;
                    int expirationDuration;
                    std::cout << "Enter your username: ";
                    std::getline(std::cin, username);
                    std::cout << "Enter message: ";
                    std::getline(std::cin, message);
                    std::cout << "Enter message expiration duration (hours): ";
                    std::cin >> expirationDuration;
                    std::cin.ignore(); 
                    chatRoom.sendMessage(username, message, expirationDuration);
                    chatRoom.displayUserStatus();
                }
                else{
                      cout << "Enter the public key of the group: ";
                      getline(cin, publicKey);
                      cout << "Enter your message to send: ";
                      getline(cin, groupMessage);
                      cout<<"Chat will be cleared after every 2 minutes!!";
                      caesar.sendGroupMessage(groupMessage, publicKey, username,2);
                }
                break;
            }
            case 6: { // Display group messages
                if(check)
                {
                    std::cout << "Enter group name: "; // using username as group name 
                    std::getline(std::cin, username); 
                    chatRoom.displayGroupMembers(username);
                    chatRoom.displayUserStatus();
                    chatRoom.showMessages();
                }
                else{
                    cout << "Enter the public key of the group: ";
                    getline(cin, publicKey);
                    cout<<"The total number of group members: ";
                    caesar.displayGroupMembers(publicKey);
                    cout<<endl;
                    caesar.displayGroupMessages(publicKey, username);
                }
                break;
            }
            case 7: { // Admin-only decrypted messages
                cout << "Enter the group public key: ";
                getline(cin, publicKey);

                cout << "Enter admin password: ";
                getline(cin, adminPassword);

                if (adminPassword == "adminpass") { // Check if the password is correct
                    caesar.setAdmin(true); // Set admin status if the password is correct
                    caesar.displayGroupMembers(publicKey);
                    cout<<endl;
                    caesar.showDecryptedMessages(publicKey);
                } else {
                    cout << "Access denied. Incorrect admin password.\n";
                }
                break;
            }
            case 8: { // Delete logs by private key (Admin-only)
                cout << "Enter admin password: ";
                getline(cin, adminPassword);

                if (adminPassword == "adminpass") {
                    caesar.setAdmin(true);  // Set admin status if the password is correct
                    cout << "Enter your private key: ";
                    getline(cin, privateKey);
                    caesar.deleteGroup(privateKey);
                    cout << "Logs deleted for the given private key.\n";
                } else {
                    cout << "Access denied. Incorrect admin password.\n";
                }
                break;
            }

            case 9: { // Kick out member (Admin-only)
                cout << "Enter admin password: ";
                getline(cin, adminPassword);

                if (adminPassword == "adminpass") {
                    caesar.setAdmin(true);  // Set admin status if the password is correct
                    cout << "Enter the public key of the group: ";
                    getline(cin, publicKey);
                    cout << "Enter username of the member to kick: ";
                    getline(cin, username);
                    caesar.kickOutMember(publicKey, username);
                    cout << "Member " << username << " kicked out of the group.\n";
                } else {
                    cout << "Access denied. Incorrect admin password.\n";
                }
                break;
            }

            case 10: { // Delete group (Admin-only)
                cout << "Enter admin password: ";
                getline(cin, adminPassword);

                if (adminPassword == "adminpass") {
                    caesar.setAdmin(true);  // Set admin status if the password is correct
                    cout << "Enter the public key of the group: ";
                    getline(cin, publicKey);
                    caesar.deleteGroup(publicKey);
                } else {
                    cout << "Access denied. Incorrect admin password.\n";
                }
                break;
            }

            case 11: { // Change User
                cout << "Enter new username: ";
                getline(cin, username); // Get the username
                cout << "Enter new private key: ";
                getline(cin, privateKey); // Get the private key

                // Validate the private key before proceeding
                if (!caesar.isValidPrivateKey(username, privateKey)) {
                    cout << "Invalid private key. Must contain at least 4 digits, 2 letters, and 1 special character.\n";
                    break; // Exit if the private key is invalid
                }

                // Prompt to confirm if the user wants to log in with the new credentials
                cout << "Do you want to log in as the new user? (y/n): ";
                char ch;
                cin >> ch;
                cin.ignore(numeric_limits<streamsize>::max(), '\n'); // Clear the input buffer

                if (ch == 'y' || ch == 'Y') {
                    // Attempt to log in with the new credentials
                    if (!caesar.login(username, privateKey)) {
                        cout << "Login failed. Invalid username or private key.\n";
                        break; // Stop here if login fails
                    } else {
                        cout << "Login successful as " << username << ".\n";

                        cout << "Do you want to join an existing group? (y/n): ";
                        char joinGroup;
                        cin >> joinGroup;
                        cin.ignore(numeric_limits<streamsize>::max(), '\n'); 

                        if (joinGroup == 'y' || joinGroup == 'Y') {
                            cout << "Enter the public key of the group: ";
                            string pk;
                            cin >> pk;
                            cout << "Enter the referal key of the group: ";
                            string ref;
                            cin>> ref;
                            cin.ignore(numeric_limits<streamsize>::max(), '\n'); 

                            if (caesar.enterGroup(pk, username,ref)) {
                                cout << "Successfully joined the group!\n";
                            } else {
                                cout << "Failed to join the group. Invalid group code or you are not invited.\n";
                            }
                        }
                    }
                } else {
                    cout << "Proceeding without login.\n";
                }

                caesar.storePrivateKey(username, privateKey);
                break;
            }
            case 12:{
                    // Register New User
                    std::cout << "Enter username: ";
                    std::getline(std::cin, username);
                    std::cout << "Enter password: ";
                    std::getline(std::cin, password);
                    std::cout << "Enter role (Admin/Standard): ";
                    std::getline(std::cin, role);
                    chatRoom.registerUser(username, password, role);
                    check = true;
                    break;
            }
            case 13:{
                    std::cout << "Enter username: ";
                    std::getline(std::cin, username);
                    std::cout << "Enter password: ";
                    std::getline(std::cin, password);
                    chatRoom.loginUser(username, password);
                    break;
            }
            case 14:{
                std::string sender, receiver, message;
                std::cout << "Enter your username: ";
                std::getline(std::cin, sender);
                std::cout << "Enter receiver's username: ";
                std::getline(std::cin, receiver);
                std::cout << "Enter message: ";
                std::getline(std::cin, message);
                chatRoom.sendPrivateMessage(sender, receiver, message);
                break;
            }
            case 15: {
                cout << "Exiting...\n";
                return 0;
            }
        }
        cout<<"\n";
        cout<<"---------------------------------------------------------------------------------------------------------------------------------------------------------\n";
    }
}