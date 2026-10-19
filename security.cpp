#include <iostream>
#include <string>
#include <cctype>

bool isValidUsername(const std::string& username) {
    if (username.length() < 3 || username.length() > 24) {
        return false;
    }

    for (unsigned char c : username) {
        if (!std::isalnum(c) && c != '_') {
            return false;
        }
    }

    return true;
}

int main() {
    std::string username;

    std::cout << "ALPHA Username Validator\n";
    std::cout << "Enter username: ";
    std::cin >> username;

    if (isValidUsername(username)) {
        std::cout << "Username format is valid.\n";
    } else {
        std::cout
            << "Invalid username. Use 3-24 letters, numbers, "
            << "or underscores.\n";
    }

    return 0;
}
