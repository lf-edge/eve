// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fstream>
#include <sstream>
#include "vtpm_api.pb.h"
#include <list>
#include <google/protobuf/io/zero_copy_stream_impl.h>

using namespace std;
using namespace google::protobuf::io;

#define CODED_STRM_HDR_LEN 4
#define SERVER_PORT 8877
#define LISTEN_BACKLOG_LIMIT 16
#define MAX_ARGS 15
#define BIN_PATH "/usr/bin/"
#define CMD_OUTPUT_FILE "cmd.output"

//Protobufs are sent in CodedStream format
//Read first CODED_STRM_HDR_LEN bytes to decode the length of
//the payload
//TBD: Revisit if length CODED_STRM_HDR_LEN is required or
//can be squeezed into 1.
google::protobuf::uint32 readHdr(char *buf)
{
    google::protobuf::uint32 size;
    google::protobuf::io::ArrayInputStream arrayStrm(buf,CODED_STRM_HDR_LEN);
    CodedInputStream CodedStrmInput(&arrayStrm);
    CodedStrmInput.ReadVarint32(&size);
    return size;
}

//Not some arbitrary commands, we allow only these commands to be executed
//from the guest domains.
std::list<string> allowed_commands = {
"tpm2_getcap",
"tpm2_createek",
"tpm2_createak",
"tpm2_create",
"tpm2_createprimary",
"tpm2_evictcontrol",
"tpm2_readpublic",
"tpm2_startauthsession",
"tpm2_policysecret",
"tpm2_activatecredential",
"tpm2_flushcontext",
"tpm2_startauthsession",
"tpm2_policysecret",
"tpm2_import",
"tpm2_flushcontext",
"tpm2_load",
"tpm2_evictcontrol",
"tpm2_hmac",
"tpm2_hash",
"tpm2_sign",
"tpm2_verifysignature",
};

static int
sendResponse (int sock, eve_tools::EveTPMResponse &response)
{
    google::protobuf::uint32 size = response.ByteSize() + CODED_STRM_HDR_LEN;
    char *resp_buffer = new char [size];
    google::protobuf::io::ArrayOutputStream aos(resp_buffer, size);
    CodedOutputStream *coded_output = new CodedOutputStream(&aos);
    coded_output->WriteVarint32(response.ByteSize());
    response.SerializeToCodedStream(coded_output);
    int sent_bytes = send(sock, (void *)resp_buffer, size, 0);
    delete(resp_buffer);
    if (sent_bytes == size) {
      return 0;
    } else {
      return -1;
    }
}

static inline bool
isCommandAllowed(string command_with_args)
{
  istringstream ss(command_with_args);
  string command;
  ss >> command;
  auto it = find(allowed_commands.begin(), allowed_commands.end(), command);
  if (it != allowed_commands.end()) {
     return true;
  }
  return false;
}

static inline bool
isFileNameAPath(string filename)
{
    return (filename.find('/') != filename.npos);
}

static int
sanitizeCmdRequest(int sock, eve_tools::EveTPMRequest &request,
                   eve_tools::EveTPMResponse &response)
{
    if (!isCommandAllowed(request.command())) {
        cout << "Not a legal command, bailing out" << std::endl;
        response.set_response("Command forbidden!");
        sendResponse(sock, response);
        return -1;
    }
    for (int i=0; i < request.expectedfiles_size(); i++) {
        std::string expectedFile = request.expectedfiles(i);
        if (isFileNameAPath(expectedFile)) {
        response.set_response("output filename should not be a path!");
        sendResponse(sock, response);
        return -1;
        }
    }
    for (int i=0; i < request.inputfiles_size(); i++) {
        const eve_tools::File& file = request.inputfiles(i);
        if (isFileNameAPath(file.name())) {
            response.set_response("input filename should not be a path!");
            sendResponse(sock, response);
            return -1;
        }
    }
    return 0;
}

//TBD: Change client library to send args in a list, rather in a single string
//till then, split the given string into command and args. Once split, launch
//the command using execve() inside a child. Parent waits for the client(i.e. command)
//to finish.
static int
execCmd (string cmd) {
    int i = 0;
    string command_alone;
    istringstream full_cmd(cmd);
    const char *path[MAX_ARGS];
    string args[MAX_ARGS];

    full_cmd >> command_alone;
    string command_with_path = BIN_PATH + command_alone;

    path[i++] = command_with_path.c_str();
    while (full_cmd >> args[i] && i < MAX_ARGS) {
        path[i] = args[i].c_str();
        i++;
    }
    path[i] = NULL;

    //spawn child process
    int child_pid = fork();
    if (child_pid < 0) {
        perror("fork failed with:");
        return -1;
    } else if (child_pid == 0) {
        //Redirect stdout and stderr to cmd.output file
        int fd = open(CMD_OUTPUT_FILE, O_CREAT|O_TRUNC|O_WRONLY, 0600);
        dup2(fd, 1);
        dup2(fd, 2);
        close(fd);

        //Flush pending stderr and stdout queues
        fflush(stderr);
        fflush(stdout);
        execve(path[0], (char **)&path, NULL);

        //We should never reach here, unless execve() itself fails
        perror("execve failed with:");
        exit(-1);
    } else {
        //Wait for child to exit, and collect the return code.
        int status;
        waitpid(child_pid, &status, 0);
        if (WIFEXITED(status)) {
            return (WEXITSTATUS(status));
        } else {
            return -1;
        }
    }
    return 0;
}

//Read size bytes from the client connection, sock
//returns 0 on success, -1 on failure.
int readMessage(int sock, google::protobuf::uint32 size)
{
    int bytecount = 0;
    char payload[size+CODED_STRM_HDR_LEN];
    eve_tools::EveTPMResponse response;
    bytecount = recv(sock, (void*)payload, size+CODED_STRM_HDR_LEN, MSG_WAITALL);
    if (bytecount < 0) {
        cerr << "Error reading further payload bytes" << std::endl;
        return -1;
    }

    //Convert CodedSInputStream into Protobuf fields
    eve_tools::EveTPMRequest request;
    google::protobuf::io::ArrayInputStream arrayStrm(payload, size+CODED_STRM_HDR_LEN);
    CodedInputStream CodedStrmInput(&arrayStrm);
    CodedStrmInput.ReadVarint32(&size);
    google::protobuf::io::CodedInputStream::Limit msgLimit =
        CodedStrmInput.PushLimit(size);
    request.ParseFromCodedStream(&CodedStrmInput);
    CodedStrmInput.PopLimit(msgLimit);

    cout << "Received command is " << request.command() << std::endl;
    if (sanitizeCmdRequest(sock, request, response) != 0) {
         return -1;
    }
    for (int i=0; i < request.inputfiles_size(); i++) {
        const eve_tools::File& file = request.inputfiles(i);
        cout << "Processing file: " << file.name() << std::endl;
        ofstream input_file;
        input_file.open(file.name(), ios::out|ios::binary);
        if (!input_file) {
            cout << "Unable to open input file for writing" << std::endl;
            return -1;
        }
        input_file << file.content();
        input_file.close();
    }

    //sync all the input files.
    sync();

    //TBD: Propagate the return code all the way to the client, via protobuf.
    execCmd(request.command());

    //sync all the output files.
    sync();

    ifstream cmdOut;
    cmdOut.open(CMD_OUTPUT_FILE, ios::in);
    if (cmdOut) {
        ostringstream cmdoutstream;
        cmdoutstream << cmdOut.rdbuf();
        response.set_response(cmdoutstream.str());
        cout << "Command output is: " << std::endl;
        cout << cmdoutstream.str() << std::endl;
        cmdOut.close();
    }
    for (int i=0; i < request.expectedfiles_size(); i++) {
        std::string expectedFile = request.expectedfiles(i);
        ifstream output_file;
        output_file.open(expectedFile, ios::in| ios::binary);
        if (!output_file) {
            cout << "Unexpected: expected file " << expectedFile
                <<  " is not present!" << std::endl;
        } else {
            ostringstream expectedFileContent;
            expectedFileContent << output_file.rdbuf();
            eve_tools::File *outputFile = response.add_outputfiles();
            outputFile->set_name(expectedFile);
            outputFile->set_content(expectedFileContent.str());
            output_file.close();
        }
    }
    //Clear all the files: inputFiles and expectedFiles
    for (int i=0; i < request.expectedfiles_size(); i++) {
        std::string expectedFile = request.expectedfiles(i);
        ostringstream command;
        command << "rm -f " << expectedFile;
        system(command.str().c_str());
    }
    for (int i=0; i < request.inputfiles_size(); i++) {
        const eve_tools::File& inputFile = request.inputfiles(i);
        ostringstream command;
        command << "rm -f " << inputFile.name();
        system(command.str().c_str());
    }
    sendResponse(sock, response);
}

int main(int argc, char *argv[])
{

    //Listen at IN_ADDR_ANY, SERVER_PORT
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    int listenSock;
    if ((listenSock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "could not create listen socket" << std::endl;
        return -1;
    }

    if ((bind(listenSock, (struct sockaddr *)&serverAddr,
                    sizeof(serverAddr))) < 0) {
        cerr << "Bind failure, aborting" << std::endl;
        return -1;
    }

    if (listen(listenSock, LISTEN_BACKLOG_LIMIT) < 0) {
        cerr << "Listen failure, aborting" << std::endl;
        return -1;
    }

    // socket address used to store client address
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen = 0;

    while (true) {
        // open a new socket to transmit data per connection
        // Wait for an incoming connection.
        // TBD: For now it is blocking call. Change it to non-blocking
        // with select() and worker threads
        int sock;
        if ((sock = accept(listenSock, (struct sockaddr *)&clientAddr,
                        &clientAddrLen)) < 0) {
            cerr << "Error in accepting client connection" << std::endl;
            return -1;
        }

        int recvBytes = 0;
        char hdrBuf[CODED_STRM_HDR_LEN];
        char *pBuf = hdrBuf;

        cout << "New connection from: " << inet_ntoa(clientAddr.sin_addr)
            << std::endl;

        recvBytes = recv(sock, pBuf, CODED_STRM_HDR_LEN, MSG_PEEK);
        if (recvBytes > 0) {
            cout << "Received new request, and parsed the hdr" << std::endl;
            readMessage(sock, readHdr(hdrBuf));
        }
        close(sock);
    }

    close(listenSock);
    return 0;
}
