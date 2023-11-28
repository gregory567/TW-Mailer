#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <iostream>
#include <iomanip>
#include "mypw.hpp"

///////////////////////////////////////////////////////////////////////////////

#define BUF 1024
// used for no arguments
// #define PORT 6543

///////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{

   // if less then 2 arguments are provided, we send an error message and information about correct usage to the client
   if (argc <= 2)
   {
      std::cerr << "Error: You must provide at least one argument." << std::endl;
      std::cerr << "Usage: " << argv[0] << " [SERVER_IP] [SERVER_PORT]" << std::endl;
      return 1;
   }

   // port number is extracted from arguments
   int port = atoi(argv[2]);
   int create_socket;
   char buffer[BUF];
   struct sockaddr_in address;
   int size;
   int isQuit = 0;

   ////////////////////////////////////////////////////////////////////////////
   // CREATE A SOCKET
   // https://man7.org/linux/man-pages/man2/socket.2.html
   // https://man7.org/linux/man-pages/man7/ip.7.html
   // https://man7.org/linux/man-pages/man7/tcp.7.html
   // IPv4, TCP (connection oriented), IP (same as server)
   if ((create_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
   {
      perror("Socket error");
      return EXIT_FAILURE;
   }

   ////////////////////////////////////////////////////////////////////////////
   // INIT ADDRESS
   // Attention: network byte order => big endian
   memset(&address, 0, sizeof(address)); // init storage with 0
   address.sin_family = AF_INET;         // IPv4
   // https://man7.org/linux/man-pages/man3/htons.3.html
   address.sin_port = htons(port);
   // https://man7.org/linux/man-pages/man3/inet_aton.3.html
   // use default localhost address in case argument is missing
   if (argc < 2)
   {
      inet_aton("127.0.0.1", &address.sin_addr);
   }
   else
   {
      inet_aton(argv[1], &address.sin_addr);
   }

   ////////////////////////////////////////////////////////////////////////////
   // CREATE A CONNECTION
   // https://man7.org/linux/man-pages/man2/connect.2.html
   if (connect(create_socket,
               (struct sockaddr *)&address,
               sizeof(address)) == -1)
   {
      // https://man7.org/linux/man-pages/man3/perror.3.html
      perror("Connect error - no server available");
      printf("Reason: %s (%d)\n", strerror(errno), errno);
      return EXIT_FAILURE;
   }

   // ignore return value of printf
   printf("Connection with server (%s) established\n",
          inet_ntoa(address.sin_addr));

   ////////////////////////////////////////////////////////////////////////////
   // RECEIVE DATA
   // https://man7.org/linux/man-pages/man2/recv.2.html
   size = recv(create_socket, buffer, BUF - 1, 0);
   if (size == -1)
   {
      perror("recv error");
   }
   else if (size == 0)
   {
      printf("Server closed remote socket\n"); // ignore error
   }
   else
   {
      buffer[size] = '\0';
      printf("Server reply: %s", buffer); // ignore error
      // std::string server_reply( buffer );
      // std::cout << "Server reply: " << server_reply << std::endl;
   }

   // auxiliary variable used to verify successful login
   int loginsuccess = 0;
   std::string command;

   // in the first while-loop, we handle all commands that are available to anonymous users
   while (loginsuccess != 1 && isQuit != 1)
   {
      std::cout << ">>";
      buffer[0] = '\0';

      std::getline(std::cin, command);

      if (command == "QUIT")
      {
         // set isQuit equal to 1 to exit the loop
         isQuit = 1;
      }
      else if (command == "LOGIN")
      {
         std::string username;
         std::string password;

         // read the user's input for the username
         std::cout << "Username: ";
         if (!std::getline(std::cin, username))
         {
            fprintf(stderr, "Error reading username\n");
            continue;
         }
         // queries user for password but hides it in the terminal
         password = getpass();

         // construct the complete message to send FHTW login credentials to the server
         std::string completeMessage = "LOGIN\n" + username + "\n" + password + "\n";

         // send the complete message to the server
         int size = completeMessage.size();
         if (send(create_socket, completeMessage.c_str(), size, 0) == -1)
         {
            perror("send error");
            break;
         }
         buffer[0] = '\0';
         // after sending, receive server response and check if the LDAP authentication process was successful
         size = recv(create_socket, buffer, BUF - 1, 0);
         if (size == -1)
         {
            perror("recv error");
            break;
         }
         else if (size == 0)
         {
            printf("Server closed remote socket\n"); // ignore error
            isQuit = 1;
            break;
         }
         else
         {
            // remove the trailing \n
            buffer[size] = '\0';

            if (strcmp(buffer, "OK") == 0)
            {
               // set loginsuccess equal to 1 to exit the loop
               loginsuccess = 1;
               std::cout << "login successful" << std::endl;
            }
            else if (strcmp(buffer, "ERR") == 0)
            {
               std::cout << "login failed: wrong username and/or password or maximum number of tries (3) exceeded. Try again in 60 seconds" << std::endl;
            }
         }
      }
      else
      {
         fprintf(stderr, "Invalid command\n");
      }
   }

   // in the second while-loop, we handle all commands that are available to authenticated users
   while (!isQuit)
   {
      std::cout << ">>";
      buffer[0] = '\0';

      std::getline(std::cin, command);
      std::cout << command << std::endl;

      if (command == "SEND")
      {
         // SEND command
         // variables for storing receiver, subject and message
         std::string receiver;
         std::string subject;
         std::string message;
         std::string statusCode;

         // read the user's input for the receiver
         std::cout << "Receiver: ";
         if (!std::getline(std::cin, receiver))
         {
            fprintf(stderr, "Error reading receiver\n");
            continue;
         }

         // read the user's input for the subject
         std::cout << "Subject: ";
         if (!std::getline(std::cin, subject))
         {
            fprintf(stderr, "Error reading subject\n");
            continue;
         }

         // read the message as multiple lines
         std::cout << "Message (end with a single dot on a line):\n";
         std::string messageLine;
         message.clear();
         while (true)
         {
            if (!std::getline(std::cin, messageLine))
            {
               fprintf(stderr, "Error reading message\n");
               break;
            }
            if (messageLine == ".")
            {
               break; // End of message
            }
            message += messageLine + "\n";
         }

         // construct the complete message to be sent to the server
         std::string completeMessage = "SEND\n" + receiver + "\n" + subject + "\n" + message + ".\n";

         // send the complete message to the server
         int size = completeMessage.size();
         if (send(create_socket, completeMessage.c_str(), size, 0) == -1)
         {
            perror("send error");
            break;
         }
         buffer[0] = '\0';
         // after sending, receive and check the server's response (OK or ERR)
         size = recv(create_socket, buffer, BUF - 1, 0);
         if (size == -1)
         {
            perror("recv error");
            break;
         }
         else if (size == 0)
         {
            printf("Server closed remote socket\n"); // ignore error
            break;
         }
         else
         {
            // remove the trailing \n
            buffer[size] = '\0';
            std::cout << buffer << std::endl;
         }
      }
      else if (command == "LIST")
      {
         // LIST command
         // construct the complete message to be sent to the server
         std::string completeMessage = "LIST\n";

         // send the complete message to the server
         int size = completeMessage.size();
         if (send(create_socket, completeMessage.c_str(), size, 0) == -1)
         {
            perror("send error");
            break;
         }

         // after sending, receive and check the server's response (OK or ERR)
         size = recv(create_socket, buffer, BUF - 1, 0);
         if (size == -1)
         {
            perror("recv error");
            break;
         }
         else if (size == 0)
         {
            printf("Server closed remote socket\n"); // ignore error
            break;
         }
         else
         {
            // Check if the response contains the message count
            int messageCount = 0;
            if (sscanf(buffer, "%d", &messageCount) == 1)
            {
               if (messageCount > 0)
               {
                  std::cout << "Server response: \n"
                            << buffer << std::endl;
               }
               else
               {
                  std::cout << "No messages for this user or user unknown." << std::endl;
               }
            }
         }
      }
      else if (command == "READ")
      {
         // READ command
         std::string messageNumber;

         // read the user's input for the message number
         std::cout << "Message Number: ";
         if (!std::getline(std::cin, messageNumber))
         {
            fprintf(stderr, "Error reading message number\n");
            continue;
         }

         // construct the complete message to be sent to the server
         std::string completeMessage = "READ\n" + messageNumber + "\n";

         // send the complete message to the server
         int size = completeMessage.size();
         if (send(create_socket, completeMessage.c_str(), size, 0) == -1)
         {
            perror("send error");
            break;
         }

         // after sending, receive and check the server's response (OK or ERR)
         size = recv(create_socket, buffer, BUF - 1, 0);
         if (size == -1)
         {
            perror("recv error");
            break;
         }
         else if (size == 0)
         {
            printf("Server closed remote socket\n"); // ignore error
            break;
         }
         else
         {
            // remove the trailing \n
            buffer[size] = '\0';
            std::cout << buffer << std::endl;
         }
         // empty buffer
         buffer[0] = '\0';
      }
      else if (command == "DEL")
      {
         // DEL command
         std::string messageNumber;

         // read the user's input for the message number
         std::cout << "Message Number: ";
         if (!std::getline(std::cin, messageNumber))
         {
            fprintf(stderr, "Error reading message number\n");
            continue;
         }

         // construct the complete message to be sent to the server
         std::string completeMessage = "DEL\n" + messageNumber + "\n";

         // send the complete message to the server
         int size = completeMessage.size();
         if (send(create_socket, completeMessage.c_str(), size, 0) == -1)
         {
            perror("send error");
            break;
         }

         // after sending, receive and check the server's response (OK or ERR)
         size = recv(create_socket, buffer, BUF - 1, 0);
         if (size == -1)
         {
            perror("recv error");
            break;
         }
         else if (size == 0)
         {
            printf("Server closed remote socket\n"); // ignore error
            break;
         }
         else
         {
            // remove the trailing \n
            buffer[size] = '\0';
            std::cout << buffer << std::endl;
         }
      }
      else if (command == "QUIT")
      {
         // set isQuit equal to 1 to exit the loop
         isQuit = 1;
      }
      else
      {
         fprintf(stderr, "Invalid command\n");
      }
   }

   ////////////////////////////////////////////////////////////////////////////
   // CLOSES THE DESCRIPTOR
   if (create_socket != -1)
   {
      if (shutdown(create_socket, SHUT_RDWR) == -1)
      {
         // invalid in case the server is gone already
         perror("shutdown create_socket");
      }
      if (close(create_socket) == -1)
      {
         perror("close create_socket");
      }
      create_socket = -1;
   }

   return EXIT_SUCCESS;
}
