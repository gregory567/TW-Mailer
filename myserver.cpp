#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <string>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <ctime>
#include <ldap.h>
#include <pthread.h>
#include <vector>

///////////////////////////////////////////////////////////////////////////////

#define BUF 1024
// #define PORT 6543
#define WAITING_CONNECTIONS 5
#define THREAD_LIMIT 50

///////////////////////////////////////////////////////////////////////////////
struct LoginAttempt
{
    std::string ipaddress;
    std::string username;
    int attempts;
};

// used by signalHandler
int abortRequested = 0;
int create_socket = -1;
int new_socket = -1;
int threadCounter = 0;

// mailspooling directory
std::string mailDir;

// stores the client login attempts
std::vector<LoginAttempt> blacklistVec;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

///////////////////////////////////////////////////////////////////////////////

void *clientCommunication(void *data);
void signalHandler(int sig);
bool username_is_correct(const std::string &username);
int getHighestMessageNr(std::string pathToUserFolder);
int ldapBind(std::string username, std::string password);
void printTime();

// functions for blacklist
std::string getClientIP(int socket);

// checks if user/ip is on blacklist
bool isBlacklisted(const std::string &blacklistFile, const std::string &username, const std::string &ipaddress);

// function adds user to blacklist. if user already on blacklist then sets the timestamp to current time
void updateBlacklist(const std::string &blacklistFile, const std::string &username, const std::string &ipaddress);

// checks if the entry is older than 60 seconds. if it is -> removes it and returns true
bool removeFromBlacklist(const std::string &blacklistFile, const std::string &username, const std::string &ipaddress);
// int argc, char **argv

///////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])

{

    if (argc <= 2)
    {
        std::cerr << "Error: You must provide at least one argument." << std::endl;
        std::cerr << "Usage: " << argv[0] << " [SERVER_PORT] [MAIL-SPOOL-DIRECTORYNAME]" << std::endl;
        return 1;
    }

    // mail-spooling directory
    mailDir = argv[2];

    // serverport
    int port = atoi(argv[1]);

    socklen_t addrlen;
    struct sockaddr_in address, cliaddress;
    int reuseValue = 1;

    // load blacklist file
    if (std::filesystem::exists("blacklist"))
    {
        std::cout << "Blacklist file already exists. Opening...\n";

        std::ifstream blacklistFile("blacklist");
        blacklistFile.close();
    }
    else
    {
        std::cout << "Blacklist file doesn't exist. Creating...\n";

        // Create the blacklist file
        std::ofstream blacklistFile("blacklist");
        blacklistFile.close();
    }

    ////////////////////////////////////////////////////////////////////////////
    // SIGNAL HANDLER
    // SIGINT (Interrup: ctrl+c)
    // https://man7.org/linux/man-pages/man2/signal.2.html
    if (signal(SIGINT, signalHandler) == SIG_ERR)
    {
        printTime();
        perror("signal can not be registered");
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // CREATE A SOCKET
    // https://man7.org/linux/man-pages/man2/socket.2.html
    // https://man7.org/linux/man-pages/man7/ip.7.html
    // https://man7.org/linux/man-pages/man7/tcp.7.html
    // IPv4, TCP (connection oriented), IP (same as client)
    if ((create_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        printTime();
        perror("Socket error"); // errno set by socket()
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // SET SOCKET OPTIONS
    // https://man7.org/linux/man-pages/man2/setsockopt.2.html
    // https://man7.org/linux/man-pages/man7/socket.7.html
    // socket, level, optname, optvalue, optlen
    if (setsockopt(create_socket, SOL_SOCKET, SO_REUSEADDR, &reuseValue, sizeof(reuseValue)) == -1)
    {
        printTime();
        perror("set socket options - reuseAddr");
        return EXIT_FAILURE;
    }

    if (setsockopt(create_socket, SOL_SOCKET, SO_REUSEPORT, &reuseValue, sizeof(reuseValue)) == -1)
    {
        printTime();
        perror("set socket options - reusePort");
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // INIT ADDRESS
    // Attention: network byte order => big endian
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    ////////////////////////////////////////////////////////////////////////////
    // ASSIGN AN ADDRESS WITH PORT TO SOCKET
    if (bind(create_socket, (struct sockaddr *)&address, sizeof(address)) == -1)
    {
        printTime();
        perror("bind error");
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // ALLOW CONNECTION ESTABLISHING
    // Socket, Backlog (= count of waiting connections allowed)
    if (listen(create_socket, WAITING_CONNECTIONS) == -1)
    {
        printTime();
        perror("listen error");
        return EXIT_FAILURE;
    }

    while (!abortRequested)
    {
        /////////////////////////////////////////////////////////////////////////
        // ignore errors here... because only information message
        // https://linux.die.net/man/3/printf
        printTime();
        printf("Waiting for connections...\n");

        /////////////////////////////////////////////////////////////////////////
        // ACCEPTS CONNECTION SETUP
        // blocking, might have an accept-error on ctrl+c
        addrlen = sizeof(struct sockaddr_in);
        if ((new_socket = accept(create_socket,
                                 (struct sockaddr *)&cliaddress,
                                 &addrlen)) == -1)
        {
            if (abortRequested)
            {
                printTime();
                perror("accept error after aborted");
            }
            else
            {
                printTime();
                perror("accept error");
            }
            break;
        }

        /////////////////////////////////////////////////////////////////////////
        // START CLIENT
        // ignore printf error handling
        printTime();
        printf("Client connected from %s:%d...\n", inet_ntoa(cliaddress.sin_addr), ntohs(cliaddress.sin_port));

        pthread_t thread;

        // allocate space on heap to store client socket descriptor for further usage in thread
        int *clientSOCK = (int *)malloc(sizeof(int));
        *clientSOCK = new_socket;
        new_socket = -1;

        // pthread_mutex_lock(&mutex);
        // in case the thread limit is reached, wait here until threads are "available" again
        while (threadCounter >= THREAD_LIMIT)
        {
            sleep(1);
        }
        // pthread_mutex_unlock(&mutex);

        // pthread_mutex_lock(&mutex);
        //  if the thread limit is not reached, create a thread for the clientCommunication function. uses the communication socket as a parameter
        if (threadCounter < THREAD_LIMIT)
        {
            if (pthread_create(&thread, NULL, clientCommunication, clientSOCK) < 0)
            {
                printTime();
                perror("could not create thread");
                return 1;
            }
        }
        // pthread_mutex_unlock(&mutex);
    }

    // frees the descriptor
    if (create_socket != -1)
    {
        if (shutdown(create_socket, SHUT_RDWR) == -1)
        {
            printTime();
            perror("shutdown create_socket");
        }
        if (close(create_socket) == -1)
        {
            printTime();
            perror("close create_socket");
        }
        create_socket = -1;
    }

    return EXIT_SUCCESS;
}

void *clientCommunication(void *data)
{
    pthread_mutex_lock(&mutex);
    threadCounter++;
    pthread_mutex_unlock(&mutex);

    // used to as condition to exit the while loops (when user sends QUIT or ctrl+c)
    int clientQuit = 0;
    char buffer[BUF];
    int size;
    int current_socket = *(int *)data;
    free(data);

    std::string clientIP = getClientIP(current_socket);
    std::string sessionUsername;

    // SEND login prompt:
    std::string tmpMessage = "Welcome to myserver !\r\n"
                             "Please type LOGIN to authenticate or QUIT to exit: \r\n";
    strcpy(buffer, tmpMessage.c_str());

    if (send(current_socket, buffer, strlen(buffer), 0) == -1)
    {
        printTime();
        std::cout << sessionUsername << " (sd:" << current_socket << ") ";
        perror("send failed");
        pthread_mutex_lock(&mutex);
        threadCounter--;
        pthread_mutex_unlock(&mutex);
        return NULL;
    }

    int userExists = 0;

    // recieve client login credentials
    while (userExists != 1 && !abortRequested)
    {
        // later used to exit loop if client sends quit
        clientQuit = 0;
        buffer[0] = '\0';
        size = recv(current_socket, buffer, BUF - 1, 0);
        if (size == -1)
        {
            if (abortRequested)
            {
                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                perror("recv error after aborted");
            }
            else
            {
                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                perror("recv error");
            }
        }

        if (size == 0)
        {
            printTime();
            std::cout << sessionUsername << " (sd:" << current_socket << ") ";
            printf("Client closed remote socket \n"); // ignore error
            // used to exit the next while loop
            // return NULL;
            clientQuit = 1;
            break;
        }

        // interpret commands
        std::string str(buffer);
        // variable to store the first line in of client message (either LOGIN or QUIT)
        std::string commandLine;
        std::string password;

        // use std::istringstream to make a stream of the buffer to parse it via getline
        std::istringstream bufferStream(buffer);

        std::getline(bufferStream, commandLine);
        std::getline(bufferStream, sessionUsername);

        // check if username and/or ipaddress is on blacklist
        pthread_mutex_lock(&mutex);
        if (isBlacklisted("blacklist", sessionUsername, clientIP))
        {
            printTime();
            std::cout << sessionUsername << " (sd:" << current_socket << ") ";
            std::cout << "User on blacklist!" << std::endl;
            // checks if the entry is older than 60 seconds. if it is -> removes it and returns true
            bool removed = removeFromBlacklist("blacklist", sessionUsername, clientIP);
            // if user/ip is still on blacklist send error to client and break and skip loops(set client quit)
            if (removed == false)
            {
                if (send(current_socket, "ERR\n", 3, 0) == -1)
                {
                    printTime();
                    std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                    perror("send answer failed");
                    pthread_mutex_lock(&mutex);
                    threadCounter--;
                    pthread_mutex_unlock(&mutex);
                    return NULL;
                }
                clientQuit = 1;
                break;
                // pthread_exit(NULL);
            }
        }
        pthread_mutex_unlock(&mutex);
        std::getline(bufferStream, password);

        // check if user exists by trying and ldap bind to the FHTW-LDAP server with username/password
        userExists = ldapBind(sessionUsername, password);

        buffer[0] = '\0';

        // if the LDAP-BIND was successfull -> user is successfully authenticated and can perform actions (send/list/read/del)
        if (userExists == 1)
        {
            if (send(current_socket, "OK\n", 2, 0) == -1)
            {
                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                perror("send answer failed");
                pthread_mutex_lock(&mutex);
                threadCounter--;
                pthread_mutex_unlock(&mutex);
                return NULL;
            }
            printTime();
            std::cout << sessionUsername << " (sd:" << current_socket << ") ";
            std::cout << "Login successful for " << sessionUsername << std::endl;
        }

        // if LDAP-BIND was not successful then send ERR to client and add username/ip to blacklistVEC and check if this is ip+username combinations third attempt
        // if it is then write to blacklist
        else
        {
            if (send(current_socket, "ERR\n", 3, 0) == -1)
            {
                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                perror("send answer failed");
                pthread_mutex_lock(&mutex);
                threadCounter--;
                pthread_mutex_unlock(&mutex);
                return NULL;
            }
            printTime();
            std::cout << sessionUsername << " (sd:" << current_socket << ") ";
            std::cout << "Wrong credentials for user: " << sessionUsername << std::endl;

            // BLACKLIST CHECK
            int entryFound = 0;
            // iterate through the blacklist Vector and check if this is the users+ipaddress third wrong login attempt
            pthread_mutex_lock(&mutex);
            for (LoginAttempt &loginAttempt : blacklistVec)
            {
                if (loginAttempt.username.compare(sessionUsername) == 0 && loginAttempt.ipaddress.compare(clientIP) == 0)
                {
                    entryFound = 1;
                    if (loginAttempt.attempts < 2)
                    {
                        loginAttempt.attempts++;
                    }
                    else if (loginAttempt.attempts == 2)
                    {
                        loginAttempt.attempts = 0;
                        printTime();
                        std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                        std::cout << "Login failed for " << sessionUsername << ". ";
                        std::cout << "Third failed login attempt for user: " << sessionUsername << ". ";
                        std::cout << "Adding user to blacklist" << std::endl;

                        updateBlacklist("blacklist", sessionUsername, clientIP);

                        // set clientQuit to 1 so exit both loops == terminate connection
                        clientQuit = 1;
                    }
                }
            }
            pthread_mutex_unlock(&mutex);
            if (clientQuit == 1)
            {
                break;
            }
            if (entryFound == 0)
            {
                // Create a struct and save it in the blacklistArr with username == sessionuseranem and ipaddress == clientIP and attempts = 1
                LoginAttempt newLoginAttempt = {clientIP, sessionUsername, 1};
                pthread_mutex_lock(&mutex);
                blacklistVec.push_back(newLoginAttempt);
                pthread_mutex_unlock(&mutex);
            }

            printTime();
            std::cout << sessionUsername << " (sd:" << current_socket << ") ";
            std::cout << "Login failed for " << sessionUsername << std::endl;
        }
    }

    while (!abortRequested && !clientQuit)
    {
        /////////////////////////////////////////////////////////////////////////
        // RECEIVE
        buffer[0] = '\0';
        size = recv(current_socket, buffer, BUF - 1, 0);
        if (size == -1)
        {
            if (abortRequested)
            {
                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                perror("recv error after aborted");
            }
            else
            {
                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                perror("recv error");
            }
            break;
        }

        if (size == 0)
        {
            printf("Client closed remote socket\n"); // ignore error
            break;
        }

        // remove ugly debug message, because of the sent newline of client
        if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
        {
            size -= 2;
        }
        else if (buffer[size - 1] == '\n')
        {
            --size;
        }

        buffer[size] = '\0';

        std::string str(buffer);
        std::string command;

        // use std::istringstream to make a stream of the buffer to parse it via getline
        std::istringstream bufferStream(buffer);

        // read the first line of the message into the 'command' variable
        if (std::getline(bufferStream, command))
        {
            printTime();
            std::cout << sessionUsername << " (sd:" << current_socket << ") ";
            std::cout << "Message received: " << std::endl
                      << buffer << std::endl;
        }
        else
        {
            printTime();
            std::cout << sessionUsername << " (sd:" << current_socket << ") ";
            std::cerr << "Failed to get command." << std::endl;
        }

        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // check which command:
        //  SEND
        //  LIST
        //  READ
        //  DEL
        //  QUIT

        // if SEND command was used save the file in the folder of the recipient (create if it does not already exist)
        if (command == "SEND")
        {
            std::string receiver;
            std::string subject;
            std::string message;
            std::string line;
            // mail spool directory (contains the folders with usernames that store the messages (1 file for each message))

            // read next line into the 'receiver' variable
            std::getline(bufferStream, receiver);
            printTime();
            std::cout << sessionUsername << " (sd:" << current_socket << ") ";
            std::cout << "receiver: " << receiver << "." << std::endl;
            // check if receiver is correct
            if (username_is_correct(receiver) == false)
            {

                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                std::cout << "receiver can only contain letters and digits" << std::endl;
                // send ERR message to client
                // check if ERR message was sent successfully
                if (send(current_socket, "ERR\n", 3, 0) == -1)
                {
                    printTime();
                    std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                    perror("send answer failed");
                    pthread_mutex_lock(&mutex);
                    threadCounter--;
                    pthread_mutex_unlock(&mutex);
                    return NULL;
                }
                continue;
            }

            // read next line into the 'subject' variable
            std::getline(bufferStream, subject);
            // if subject is > 80 chars send ERR message
            if (subject.length() > 80)
            {
                // send ERR message to client
                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                std::cout << "Subject too long ( >80 chars)" << std::endl;
                // check if ERR message was sent successfully
                if (send(current_socket, "ERR\n", 3, 0) == -1)
                {
                    printTime();
                    std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                    perror("send answer failed");
                    pthread_mutex_lock(&mutex);
                    threadCounter--;
                    pthread_mutex_unlock(&mutex);
                    return NULL;
                }
                continue;
            }

            // read lines into the 'message' variable until single dot on a new line is encountered
            while (std::getline(bufferStream, line))
            {
                // exit the loop when a single dot on a new line is encountered
                if (line == ".")
                {
                    break;
                }
                // append line to message
                message += line + "\n";
            }

            // lock here due to filesystem access
            pthread_mutex_lock(&mutex);
            // check if mail spool directory already exists
            if (!std::filesystem::exists(mailDir))
            {
                // create if it does not exist
                if (std::filesystem::create_directory(mailDir))
                {
                    printTime();
                    std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                    std::cout << "Directory created: " << mailDir << std::endl;
                }
                else
                {
                    printTime();
                    std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                    std::cerr << "Failed to create the directory: " << mailDir << std::endl;
                    break;
                }
            }
            pthread_mutex_unlock(&mutex);
            pthread_mutex_lock(&mutex);
            // path to user/receiver folder
            std::string pathToUserFolder = mailDir + "/" + receiver;
            // check if folder exists
            if (!std::filesystem::exists(pathToUserFolder))
            {
                // create if it does not exist
                if (std::filesystem::create_directory(pathToUserFolder))
                {
                    printTime();
                    std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                    std::cout << "Directory created: " << pathToUserFolder << std::endl;
                }
                else
                {
                    printTime();
                    std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                    std::cerr << "Unable to create the directory: " << pathToUserFolder << std::endl;
                    break;
                }
            }
            pthread_mutex_unlock(&mutex);

            // get the highest message number from receiver folder to use as the next filename
            pthread_mutex_lock(&mutex);
            int highestNr = getHighestMessageNr(pathToUserFolder);
            highestNr++;
            pthread_mutex_unlock(&mutex);

            pthread_mutex_lock(&mutex);
            // create an ofstream object/file and open the file
            std::ofstream outfile(pathToUserFolder + "/" + std::to_string(highestNr));

            // write complete message in file
            if (outfile.is_open())
            {
                outfile << sessionUsername << std::endl;
                outfile << receiver << std::endl;
                outfile << subject << std::endl;
                outfile << message;

                // close file
                outfile.close();

                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                std::cout << "File created successfully: " << highestNr << std::endl;
            }

            else
            {
                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                std::cerr << "Unable to create the file: " << highestNr << std::endl;
            }
            pthread_mutex_unlock(&mutex);

            // check if OK was sent successfully
            if (send(current_socket, "OK\n", 2, 0) == -1)
            {
                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                perror("send answer failed");
                pthread_mutex_lock(&mutex);
                threadCounter--;
                pthread_mutex_unlock(&mutex);
                return NULL;
            }
        }
        // LIST command is used to list all received messages from users inbox
        else if (command == "LIST")
        {

            std::string pathToUserFolder = mailDir + "/" + sessionUsername;
            int msgCounter = 0;
            std::cout << pathToUserFolder << std::endl;
            // check if the username/folder already exists
            pthread_mutex_lock(&mutex);
            if (std::filesystem::exists(pathToUserFolder))
            {
                std::cout << pathToUserFolder << std::endl;
                std::string subjects;
                for (const auto &entry : std::filesystem::directory_iterator(pathToUserFolder))
                {
                    std::ifstream file(entry.path());

                    // Check if the file is open
                    if (file.is_open())
                    {
                        // Read the third line and append it to the 'subjects' variable
                        std::string line;
                        for (int i = 1; i <= 3; i++)
                        {
                            if (std::getline(file, line) && i == 3)
                            {
                                subjects += line + "\n";
                            }
                        }
                        // increment the message counter
                        msgCounter++;
                        // Close the file
                        file.close();
                    }
                }

                // append the final message counter to the subjects variable
                subjects = std::to_string(msgCounter) + "\n" + subjects;
                // if message count is 0
                if (subjects.empty())
                {
                    // send '0' to the client, because the folder did not contain any messages
                    if (send(current_socket, "0", 3, 0) == -1)
                    {
                        printTime();
                        std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                        perror("send answer failed");

                        threadCounter--;

                        return NULL;
                    }
                }
                else
                {
                    strcpy(buffer, subjects.c_str());

                    // check if sending was successful
                    if (send(current_socket, buffer, BUF - 1, 0) == -1)
                    {
                        printTime();
                        std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                        perror("send answer failed");

                        threadCounter--;

                        return NULL;
                    }
                }
            }
            else
            {
                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                std::cout << "No messages for this user or user unknown." << std::endl;
                // send '0' to the client, because the username/folder does not exist yet
                if (send(current_socket, "0", 3, 0) == -1)
                {
                    printTime();
                    std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                    perror("send answer failed");

                    threadCounter--;

                    return NULL;
                }
            }
            pthread_mutex_unlock(&mutex);
        }

        // READ command is used to display a specific message of current sessionUser (loged in user)
        else if (command == "READ")
        {
            pthread_mutex_lock(&mutex);
            // messageNr from client
            std::string messageNr;
            // used to store the message in
            std::string msg;

            // read messageNr from the buffer
            std::getline(bufferStream, messageNr);

            // if user input for messageNr was not an int return ERR
            try
            {
                std::stoi(messageNr);
            }
            catch (const std::invalid_argument &e)
            {
                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                std::cerr << "messageNr not an integer  " << e.what() << std::endl;
            }

            std::string pathToUserFolder = mailDir + "/" + sessionUsername;

            // if the username/folder exists, search for the message

            if (std::filesystem::exists(pathToUserFolder))
            {

                // iterate through files in user folder
                for (const auto &entry : std::filesystem::directory_iterator(pathToUserFolder))
                {
                    // if msg counter == messageNr open file and save content to msg
                    if (entry.path().filename() == messageNr)
                    {
                        std::ifstream file(entry.path());
                        // iterate through the found file and save it line by line into msg
                        if (file.is_open())
                        {
                            std::string line;
                            while (std::getline(file, line))
                            {
                                msg += line;
                                msg += '\n';
                            }
                            file.close();
                        }
                        else
                        {
                            printTime();
                            std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                            std::cerr << "Failed to open the file." << std::endl;
                        }
                        break;
                    }
                }
            }

            else
            {
                // the username/folder does not exist, send ERR message
                if (send(current_socket, "ERR\n", 3, 0) == -1)
                {
                    printTime();
                    std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                    perror("send answer failed");
                    threadCounter--;
                    return NULL;
                }
                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                std::cout << "no messages for " << sessionUsername << std::endl;
                // continue;
            }

            // if the folder exists but there was no matching message for the desired message number, send ERR message
            if (std::filesystem::exists(pathToUserFolder) && msg.empty())
            {
                if (send(current_socket, "ERR\n", 3, 0) == -1)
                {
                    printTime();
                    std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                    perror("send answer failed");

                    threadCounter--;

                    return NULL;
                }
                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                std::cout << "no message found for this message number: " << buffer << std::endl;
            }
            else if (!msg.empty())
            {
                // append an OK in front of the message body
                msg = "OK\n" + msg;

                buffer[0] = '\0';

                strcpy(buffer, msg.c_str());
                int size = msg.size();
                // check if sending was successful
                if (send(current_socket, msg.c_str(), size, 0) == -1)
                {
                    printTime();
                    std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                    perror("send answer failed");

                    threadCounter--;

                    return NULL;
                }
            }
            pthread_mutex_unlock(&mutex);
        }
        else if (command == "DEL")
        {
            // DEL command is used to remove a specific message for current sessionUser (logged in user)
            std::string messageNr;

            // read messageNr from the buffer
            std::getline(bufferStream, messageNr);

            // check if user entered invalid message number
            if (stoi(messageNr) < 1)
            {
                if (send(current_socket, "ERR\n", 3, 0) == -1)
                {
                    printTime();
                    std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                    perror("send answer failed");
                    pthread_mutex_lock(&mutex);
                    threadCounter--;
                    pthread_mutex_unlock(&mutex);
                    return NULL;
                }
                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                std::cout << "Invalid message number (< 1): " << messageNr << std::endl;
                pthread_mutex_lock(&mutex);
                threadCounter--;
                pthread_mutex_unlock(&mutex);
                return NULL;
            }

            std::string pathToUserFolder = mailDir + "/" + sessionUsername;

            // if the username/folder already exists, search for the message
            pthread_mutex_lock(&mutex);
            if (std::filesystem::exists(pathToUserFolder))
            {
                int fileFound = 0;
                // iterate through files in user folder
                for (const auto &entry : std::filesystem::directory_iterator(pathToUserFolder))
                {
                    // if msgCounter == messageNr delete file
                    if (entry.path().filename() == messageNr)
                    {
                        try
                        {
                            // delete the found file
                            fileFound = 1;
                            std::filesystem::remove(entry.path());
                            printTime();
                            std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                            std::cout << "File deleted successfully." << std::endl;
                            // send OK message to the client
                            if (send(current_socket, "OK\n", 2, 0) == -1)
                            {
                                perror("send answer failed");
                                threadCounter--;
                                return NULL;
                            }
                        }
                        catch (const std::filesystem::filesystem_error &e)
                        {
                            printTime();
                            std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                            std::cerr << "Error deleting the file: " << e.what() << std::endl;
                            // send ERR message to the client
                            if (send(current_socket, "ERR\n", 3, 0) == -1)
                            {
                                printTime();
                                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                                perror("send answer failed");
                                threadCounter--;
                                return NULL;
                            }
                        }
                        break;
                    }
                }
                if (fileFound == 0)
                {
                    // if there was no matching messageNr for sessionUser, send ERR message
                    if (send(current_socket, "ERR\n", 3, 0) == -1)
                    {
                        printTime();
                        std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                        perror("send answer failed");
                        threadCounter--;
                        return NULL;
                    }
                    printTime();
                    std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                    std::cout << "No messages to delete for " << sessionUsername << " with message number " << messageNr << std::endl;
                }
            }
            else
            {
                // if there was no username/folder to be found, send ERR message
                if (send(current_socket, "ERR\n", 3, 0) == -1)
                {
                    printTime();
                    std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                    perror("send answer failed");
                    threadCounter--;
                    return NULL;
                }
                printTime();
                std::cout << sessionUsername << " (sd:" << current_socket << ") ";
                std::cout << "User folder does not exist " << sessionUsername << std::endl;
            }
            pthread_mutex_unlock(&mutex);
        }
    }

    // closes/frees the descriptor if not already
    if (current_socket != -1)
    {

        if (shutdown(current_socket, SHUT_RDWR) == -1)
        {
            printTime();
            std::cout << sessionUsername << " (sd:" << current_socket << ") ";
            perror("shutdown current_socket");
        }

        if (close(current_socket) == -1)
        {
            printTime();
            std::cout << sessionUsername << " (sd:" << current_socket << ") ";
            perror("close current_socket");
        }
        current_socket = -1;
    }
    pthread_mutex_lock(&mutex);
    threadCounter--;
    pthread_mutex_unlock(&mutex);

    return NULL;
}

// handles SIGINT (CTRL-C) gets called asynchronously
void signalHandler(int sig)
{
    if (sig == SIGINT)
    {
        printTime();
        std::cout << "abort Requested... "; // ignore error
        abortRequested = 1;
        /////////////////////////////////////////////////////////////////////////
        // With shutdown() one can initiate normal TCP close sequence ignoring
        // the reference count.
        // https://beej.us/guide/bgnet/html/#close-and-shutdownget-outta-my-face
        // https://linux.die.net/man/3/shutdown
        if (new_socket != -1)
        {
            if (shutdown(new_socket, SHUT_RDWR) == -1)
            {
                printTime();
                perror("shutdown new_socket");
            }
            if (close(new_socket) == -1)
            {
                printTime();
                perror("close new_socket");
            }
            new_socket = -1;
        }

        if (create_socket != -1)
        {
            if (shutdown(create_socket, SHUT_RDWR) == -1)
            {
                printTime();

                perror("shutdown create_socket");
            }
            if (close(create_socket) == -1)
            {
                printTime();
                perror("close create_socket");
            }
            create_socket = -1;
        }
    }
    else
    {
        exit(sig);
    }
}

bool username_is_correct(const std::string &username)
{
    // Check if the length of the username is less than or equal to 8
    if (username.length() > 8)
    {
        return false; // Username too long
    }

    // Check if the username contains only lowercase letters and digits
    for (char c : username)
    {
        if (!std::isalnum(c) && !std::islower(c))
        {
            return false; // Username contains invalid characters.
        }
    }

    return true; // Username is valid.
}

// iterate through files in user folder and returns the number of messages in that folder
int getHighestMessageNr(std::string pathToUserFolder)
{

    int msgCounter = 0;
    // iterate through files in user folder
    for (const auto &entry : std::filesystem::directory_iterator(pathToUserFolder))
    {
        std::string fileName = entry.path().filename();
        if (std::stoi(fileName) > msgCounter)
        {
            msgCounter = std::stoi(fileName);
        }
    }
    return msgCounter;
}

int ldapBind(std::string username, std::string password)
{
    const char *ldapUri = "ldap://ldap.technikum-wien.at:389";
    const int ldapVersion = LDAP_VERSION3;
    // return code
    int rc = 0;

    ////////////////////////////////////////////////////////////////////////////
    // setup LDAP connection
    // https://linux.die.net/man/3/ldap_initialize
    LDAP *ldapHandle;
    rc = ldap_initialize(&ldapHandle, ldapUri);
    if (rc != LDAP_SUCCESS)
    {
        fprintf(stderr, "ldap_init failed\n");
        return EXIT_FAILURE;
    }
    printTime();
    std::cout << "connected to LDAP server" << ldapUri << std::endl;

    ////////////////////////////////////////////////////////////////////////////
    // set verison options
    // https://linux.die.net/man/3/ldap_set_option
    rc = ldap_set_option(
        ldapHandle,
        LDAP_OPT_PROTOCOL_VERSION, // OPTION
        &ldapVersion);             // IN-Value
    if (rc != LDAP_OPT_SUCCESS)
    {
        // https://www.openldap.org/software/man.cgi?query=ldap_err2string&sektion=3&apropos=0&manpath=OpenLDAP+2.4-Release
        printTime();
        fprintf(stderr, "ldap_set_option(PROTOCOL_VERSION): %s\n", ldap_err2string(rc));
        ldap_unbind_ext_s(ldapHandle, NULL, NULL);
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // start connection secure (initialize TLS)
    // https://linux.die.net/man/3/ldap_start_tls_s
    // int ldap_start_tls_s(LDAP *ld,
    //                      LDAPControl **serverctrls,
    //                      LDAPControl **clientctrls);
    // https://linux.die.net/man/3/ldap
    // https://docs.oracle.com/cd/E19957-01/817-6707/controls.html
    //    The LDAPv3, as documented in RFC 2251 - Lightweight Directory Access
    //    Protocol (v3) (http://www.faqs.org/rfcs/rfc2251.html), allows clients
    //    and servers to use controls as a mechanism for extending an LDAP
    //    operation. A control is a way to specify additional information as
    //    part of a request and a response. For example, a client can send a
    //    control to a server as part of a search request to indicate that the
    //    server should sort the search results before sending the results back
    //    to the client.
    rc = ldap_start_tls_s(
        ldapHandle,
        NULL,
        NULL);
    if (rc != LDAP_SUCCESS)
    {
        printTime();
        fprintf(stderr, "ldap_start_tls_s(): %s\n", ldap_err2string(rc));
        ldap_unbind_ext_s(ldapHandle, NULL, NULL);
        return EXIT_FAILURE;
    }

    ////////////////////////////////////////////////////////////////////////////
    // bind credentials
    // https://linux.die.net/man/3/lber-types
    // SASL (Simple Authentication and Security Layer)
    // https://linux.die.net/man/3/ldap_sasl_bind_s
    // int ldap_sasl_bind_s(
    //       LDAP *ld,
    //       const char *dn,
    //       const char *mechanism,
    //       struct berval *cred,
    //       LDAPControl *sctrls[],
    //       LDAPControl *cctrls[],
    //       struct berval **servercredp);

    std::string ldapBindUser = "uid=" + username + ",ou=people,dc=technikum-wien,dc=at";

    BerValue bindCredentials;
    bindCredentials.bv_val = (char *)password.c_str();
    bindCredentials.bv_len = strlen(password.c_str());
    BerValue *servercredp; // server's credentials
    rc = ldap_sasl_bind_s(
        ldapHandle,
        ldapBindUser.c_str(),
        LDAP_SASL_SIMPLE,
        &bindCredentials,
        NULL,
        NULL,
        &servercredp);
    if (rc != LDAP_SUCCESS)
    {
        fprintf(stderr, "LDAP bind error: %s\n", ldap_err2string(rc));
        ldap_unbind_ext_s(ldapHandle, NULL, NULL);
        return 0;
    }
    else
    {
        return 1;
    }
}

// prints current time in square brackets []
void printTime()
{
    auto timenow = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    std::string time = ctime(&timenow);
    // remove trailing \n
    time.pop_back();

    // old version, ] gets printed in newline
    std::cout << "[" << time << "] ";
}

// extracts and returns the clients IP address out of the communication socket
std::string getClientIP(int socket)
{

    // used to to extract the client ipaddress
    struct sockaddr_in client_address;
    socklen_t client_addrlen = sizeof(client_address);

    // getpeername function extracts ipaddress of a socket
    if (getpeername(socket, (struct sockaddr *)&client_address, &client_addrlen) == -1)
    {
        perror("getpeername error");
        close(socket);

        pthread_exit(NULL);
    }

    // std::string clientIP;
    char tempIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_address.sin_addr), tempIP, INET_ADDRSTRLEN);

    std::string clientIP = tempIP;
    return clientIP;
}

// checks if user/ipaddress is on blacklist
bool isBlacklisted(const std::string &blacklistFile, const std::string &username, const std::string &ipaddress)
{

    std::ifstream file(blacklistFile);
    std::string line;

    // Checks if the position is not equal to std::string::npos
    // std::string::npos is a constant representing the largest possible size_t value,
    // indicating that the substring was not found in the line

    while (std::getline(file, line))
    {
        size_t pos = line.find(username + " " + ipaddress);
        if (pos != std::string::npos)
        {
            file.close();
            return true;
        }
    }

    file.close();
    return false;
}

// function adds user to blacklist. if user already on blacklist then sets the timestamp to current time
void updateBlacklist(const std::string &blacklistFile, const std::string &username, const std::string &ipaddress)
{
    std::ifstream inFile(blacklistFile);
    std::vector<std::string> lines;
    std::string line;

    // reads blacklistfile and stores each line in vector
    while (std::getline(inFile, line))
    {
        lines.push_back(line);
    }

    inFile.close();

    std::ofstream outFile(blacklistFile);

    bool lineExists = false;
    // iterates through the lines vector
    for (const std::string &l : lines)
    {
        size_t pos = l.find(username + " " + ipaddress);
        // std::string::npos is a constant representing the largest possible size_t value,
        // indicating that the substring was not found in the line
        // if pos != npos -> string was found in vector -> username/ipaddress on blacklist
        if (pos != std::string::npos)
        {
            lineExists = true;
            // update timestampwith current time
            outFile << username << " " << ipaddress << " " << std::time(0) << std::endl;
        }
        else
        {
            outFile << l << std::endl;
        }
    }

    // if line does not exist create new entry with username, ipaddress, and current timestamp
    if (!lineExists)
    {
        outFile << username << " " << ipaddress << " " << std::time(0) << std::endl;
    }
    outFile.close();
}

// checks if the time difference between current timestamp and timestamp of entry is > 60. if it is the entry (user/ip) gets removed from the blacklist
// returns true if it was removed
bool removeFromBlacklist(const std::string &blacklistFile, const std::string &username, const std::string &ipaddress)
{
    std::ifstream inFile(blacklistFile);
    std::vector<std::string> lines;
    std::string line;
    bool removed = false;
    // read file and store each line in lines
    while (std::getline(inFile, line))
    {
        lines.push_back(line);
    }
    inFile.close();

    std::ofstream outFile(blacklistFile);
    // iterate through lines vector
    for (const std::string &l : lines)
    {
        // extract/split the line into username, ipaddress, and timestamp
        std::istringstream iss(l);
        std::string entryUsername, entryIP, timestampString;
        iss >> entryUsername >> entryIP >> timestampString;

        time_t timestamp = std::stoi(timestampString);

        // get current time
        time_t currentTime = std::time(nullptr);
        // if difference between current time and timestamp of entry is > 60 then dont write this line to the file
        if (entryUsername == username && entryIP == ipaddress && currentTime - timestamp > 60)
        {
            removed = true;
            // if entry is found skip it. this effectively removes it from the blacklist file
            continue;
        }
        else
        {
            // write entry again in file
            outFile << l << std::endl;
        }
    }
    outFile.close();

    return removed;
}