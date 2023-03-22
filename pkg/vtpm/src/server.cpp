// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#define _XOPEN_SOURCE 500
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ftw.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
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
#define MAX_ARGS 25
#define BIN_PATH "/usr/bin/"
#define CLIENT_READ_TIMEOUT 60  //seconds
#define failure -1
#define success 0

//Working list of arguments
thread_local string args[MAX_ARGS];
thread_local string cmdWithPath;
thread_local string clientWorkingDir;
string cmdOutputFile("cmd.output");

//Protobufs are sent in CodedStream format.
//Read first CODED_STRM_HDR_LEN bytes to decode the length of
//the payload
//TBD: Revisit if length CODED_STRM_HDR_LEN is required, or
//can be squeezed into 1.
google::protobuf::uint32
readHdr (char *buf)
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
"tpm2_readpublic",
"tpm2_policysecret",
"tpm2_startauthsession",
"tpm2_activatecredential",
"tpm2_flushcontext",
"tpm2_selftest",
"tpm2_import",
"tpm2_load",
"tpm2_hmac",
"tpm2_hash",
"tpm2_sign",
"tpm2_verifysignature",
};

//Helper callback to be used in nftw()
int
walkCb(const char *fpath, const struct stat *sb, int typeflag,
       struct FTW *ftwbuf)
{
    return remove(fpath);
}

//Delete the given (possibly non-empty)directory
static void
rmClientWorkingDir(const char *path)
{
    if (nftw(path, walkCb, 64, FTW_DEPTH | FTW_PHYS) < 0) {
        int rc = errno;
        cerr << "nftw() failed, " << strerror(rc) << std::endl;
    }
}

// Send the given response to the given socket, after converting
// response to Serialized Coded Stream.
// Returns non-zero error in case of failure.
static int
sendResponse (int sock, eve_tools::EveTPMResponse &response)
{
    int rc = success;
    google::protobuf::uint32 size = response.ByteSize() + CODED_STRM_HDR_LEN;
    char *resp_buffer = new char [size];
    google::protobuf::io::ArrayOutputStream aos(resp_buffer, size);
    CodedOutputStream *coded_output = new CodedOutputStream(&aos);
    if (!coded_output) {
        cerr << "Unable to create CodedOutputStream" << std::endl;
        rc = failure;
        goto cleanup_and_exit;
    }
    coded_output->WriteVarint32(response.ByteSize());
    if (!response.SerializeToCodedStream(coded_output)) {
        cerr << "Serialization error" << std::endl;
        rc = failure;
        goto cleanup_and_exit;
    }
    if (send(sock, (void *)resp_buffer, size, 0) != size) {
      rc = failure;
    }
    //Fall through for cleanup and exit
cleanup_and_exit:
   if (coded_output) {
       delete(coded_output);
   }
   if (resp_buffer) {
       delete(resp_buffer);
   }
   return rc;
}

//Check if this command is allowed to be executed.
static inline bool
isCommandAllowed (string command)
{
  auto it = find(allowed_commands.begin(), allowed_commands.end(), command);
  if (it != allowed_commands.end()) {
     return true;
  }
  return false;
}

//Check if filename is a path. e.g. /foo/bar
static inline bool
isFileNameAPath (string filename)
{
    return (filename.find('/') != filename.npos);
}

//Check for malformed or illegal arguments, if so, set the
//response message accordingly, and return error to the
//caller
static int
sanitizeCmdRequest (int sock, eve_tools::EveTPMRequest &request,
                   eve_tools::EveTPMResponse &response)
{
    int rc = success;

    //pull just the command (w/o args) from request.
    istringstream ss(request.command());
    string command;
    ss >> command;

    //If command is not one of the allowed group, reject it.
    if (!isCommandAllowed(command)) {
        cerr << "Not a legal command, bailing out" << std::endl;
        response.set_response(command + ":" + "Command is forbidden!");
        rc = failure;
        goto cleanup_and_exit;
    }

    //If input or output file name contains a path (e.g. /foo/bar)
    for (int i=0; i < request.expectedfiles_size(); i++) {
        std::string expectedFile = request.expectedfiles(i);
        if (isFileNameAPath(expectedFile)) {
            response.set_response(expectedFile + ":" +
                                  "output filename should not be a path!");
            rc = failure;
            goto cleanup_and_exit;
        }
    }
    for (int i=0; i < request.inputfiles_size(); i++) {
        const eve_tools::File& file = request.inputfiles(i);
        if (isFileNameAPath(file.name())) {
            response.set_response(file.name() + ":" +
                                  "input filename should not be a path!");
            return rc;
            goto cleanup_and_exit;
        }
    }
cleanup_and_exit:
    return rc;
}

//Prepare execve args list, from the give command.
//Returns failure in case of too many arguments.
static inline int
prepareCommand(string cmd,
               const char **cmdArgs,
               eve_tools::EveTPMResponse &response) {
    int i = 0, j = 0, rc = success;
    string cmdAlone;
    istringstream fullCmd(cmd);

    fullCmd >> cmdAlone;
    cmdAlone.erase(0, cmdAlone.find("_") + 1); // +1 for size of "_"
    cmdWithPath = BIN_PATH + string("tpm2");

    cmdArgs[i++] = strdup(cmdWithPath.c_str());
    cmdArgs[i++] = strdup(cmdAlone.c_str());
    while (fullCmd >> args[i] && i < (MAX_ARGS - 1)) {
        cmdArgs[i] = strdup(args[i].c_str());
        i++;
    }
    cmdArgs[i] = NULL;

    if (i == (MAX_ARGS - 1)) {
        cerr << "More than acceptable number of args" << std::endl;
        response.set_response("Too many arguments");
        rc = failure;
        goto cleanup_and_exit;
    }
    cmdArgs[i] = NULL;

    //print for debugging purposes
    cout << "Prepared command is :" << std::endl;
    while(cmdArgs[j]) {
      cout << cmdArgs[j++] << " ";
    }
    cout << std::endl;
    return rc;

cleanup_and_exit:
    for (int i = 0; cmdArgs[i]; i++) {
        free((void *)cmdArgs[i]);
        cmdArgs[i] = NULL;
    }

    return rc;
}

//TBD: Change client library to send args in a list, rather in a single string
//till then, split the given string into command and args. Once split, launch
//the command using execve() inside a child. Parent waits for the client(i.e. command)
//to finish.
static int
execCmd (const char **cmdArgs) {
    //spawn child process
    pid_t child_pid = fork();
    if (child_pid < 0) {
        int rc = errno;
        cerr << "fork() failed with errno " << rc << std::endl;
        return(rc);
    } else if (child_pid == 0) {
        //Change the working directory of child to client specific
        //directory.
        if (chdir(clientWorkingDir.c_str()) < 0 ) {
            int rc = errno;
            cerr << "chdir() failed with errno " << rc << std::endl;
            exit(rc);
        }
        //Redirect stdout and stderr to cmd.output file
        int fd = open(cmdOutputFile.c_str(), O_CREAT|O_TRUNC|O_WRONLY, 0600);
        if (fd < 0) {
            int rc = errno;
            cerr << "open() failed. error/path " << strerror(rc)
                 << (clientWorkingDir + "/" + cmdOutputFile).c_str() << std::endl;
            exit(rc);
        }
        dup2(fd, 1);
        dup2(fd, 2);
        close(fd);

        //Flush pending stderr and stdout queues
        fflush(stderr);
        fflush(stdout);
        if (execve(cmdArgs[0], (char * const*)cmdArgs, NULL) < 0) {
            int rc = errno;
            cerr << "execve() failed with errno " << rc << std::endl;
            exit(rc);
        }
    } else {
        //Wait for child to exit, and collect the return code.
        int status;
        waitpid(child_pid, &status, 0);
        if (WIFEXITED(status)) {
            return (WEXITSTATUS(status));
        } else {
            return failure;
        }
    }
    return 0;
}

// Given the socket, and the size of the request payload,
// receive complete request payload, convert from serialized
// coded stream format into protobuf format in eve_tools::EveTpmRequest.
// Returns non-zero error code in case of failure, and fills up
// response.response() with appropriate error message.
static int
parseRequest(int sock,
             google::protobuf::uint32 size,
             eve_tools::EveTPMRequest &request,
             eve_tools::EveTPMResponse &response,
             char *payload)
{
    int byteCnt = 0;
    ifstream cmdOut;

    //We expect at least one byte to read here.
    if (size == 0) {
        response.set_response("Invalid request length:" + to_string(size));
        return failure;
    }

    byteCnt = recv(sock, (void*)payload, size+CODED_STRM_HDR_LEN, MSG_WAITALL);
    if (byteCnt < 0) {
        int err = errno;
        cerr << "Error reading further payload bytes:"
             << strerror(err) << std::endl;
        response.set_response("recv() failure" + string(strerror(err)));
        return failure;
    }

    //Convert CodedSInputStream into Protobuf fields
    google::protobuf::io::ArrayInputStream arrayStrm(payload, size+CODED_STRM_HDR_LEN);
    CodedInputStream CodedStrmInput(&arrayStrm);
    CodedStrmInput.ReadVarint32(&size);
    google::protobuf::io::CodedInputStream::Limit msgLimit =
        CodedStrmInput.PushLimit(size);
    if (!request.ParseFromCodedStream(&CodedStrmInput)) {
        cerr << "Incorrect CodedStream format or read error" << std::endl;
        response.set_response("Incorrect request format");
        return failure;
    }
    CodedStrmInput.PopLimit(msgLimit);
    return success;
}

//Handle an incoming request from socket. Size of
//the request message(excluding the CodedStream header)
//is given as input.
//Returns non-zero error on failure.
int
handleRequest (int sock, google::protobuf::uint32 size)
{
    char payload[size+CODED_STRM_HDR_LEN];
    eve_tools::EveTPMRequest request;
    eve_tools::EveTPMResponse response;
    int byteCnt = 0, rc = success;
    const char *cmdArgs[MAX_ARGS+1];
    ifstream cmdOut;

    if (parseRequest(sock, size, request, response, payload) < 0) {
        sendResponse(sock, response);
        rc = failure;
        goto cleanup_and_exit;
    }

    if (sanitizeCmdRequest(sock, request, response) != 0) {
        //send the error set by sanitizeCmdRequest to client.
        sendResponse(sock, response);
        rc = failure;
        goto cleanup_and_exit;
    }

    if (mkdir(clientWorkingDir.c_str(), 0700) < 0 ) {
        int rc = errno;
        cerr << "Unable to create client specific working dir "
             << clientWorkingDir << ": "
             << string(strerror(rc)) << std::endl;
        response.set_response("Unable to create client specific working dir: "
                               + string(strerror(rc)));
        sendResponse(sock, response);
        goto cleanup_and_exit;
    }

    if (prepareCommand(request.command(), cmdArgs, response) < 0) {
        sendResponse(sock, response);
        rc = failure;
        goto cleanup_and_exit;
    }
    //Prepare input files expected by the command.
    for (int i=0; i < request.inputfiles_size(); i++) {
        const eve_tools::File& file = request.inputfiles(i);
        ofstream input_file;
        input_file.open(clientWorkingDir + "/" + file.name(),
                        ios::out|ios::binary);
        if (!input_file) {
            cerr << "Unable to open file for writing input contents: "
                 << file.name() << std::endl;
            response.set_response("Unable to open input file " + file.name());
            sendResponse(sock, response);
            rc = failure;
            goto cleanup_and_exit;
        }
        input_file << file.content();
        input_file.close();
    }

    //sync all the input files.
    sync();

    rc = execCmd(cmdArgs);
    if (rc != 0) {
        cerr << "Command invocation failed with rc " << rc << std::endl;
        response.set_response("Backend failure while serving the request: Error "
                               + to_string(rc));
        sendResponse(sock, response);
        rc = failure;
        goto cleanup_and_exit;
    }

    //sync all the output files.
    sync();

    //Pack stderr/stdout from command invocation.
    cmdOut.open(clientWorkingDir + "/" + cmdOutputFile, ios::in);
    if (cmdOut) {
        ostringstream cmdoutstream;
        //cmdOut could be empty, not an error.
        cmdoutstream << cmdOut.rdbuf();
        cout << "Command output is: " << std::endl
             << cmdoutstream.str() << std::endl;
        response.set_response(cmdoutstream.str());
        cmdOut.close();
    }

    //Pack output files expected by the client, from the command.
    for (int i=0; i < request.expectedfiles_size(); i++) {
        std::string expectedFile = request.expectedfiles(i);
        ifstream output_file;
        output_file.open(clientWorkingDir + "/" + expectedFile,
                         ios::in| ios::binary);
        if (!output_file) {
            cerr << "Unexpected: expected file " << expectedFile
                <<  " is not present!" << std::endl;
            response.set_response("Expected file not found " + expectedFile);
            sendResponse(sock, response);
            rc = failure;
            goto cleanup_and_exit;
        } else {
            ostringstream expectedFileContent;
            expectedFileContent << output_file.rdbuf();
            eve_tools::File *outputFile = response.add_outputfiles();
            outputFile->set_name(expectedFile);
            outputFile->set_content(expectedFileContent.str());
            output_file.close();
        }
    }
    sendResponse(sock, response);
    //fall through for cleanup and exit

cleanup_and_exit:
    if (cmdOut) {
        cmdOut.close();
    }

    // clean up the duplicate strings memory
    if (cmdArgs[0] != NULL) {
        for (int i=0; cmdArgs[i]; i++)
            free((void *)cmdArgs[i]);
    }

    // Remove the working directory
    rmClientWorkingDir(clientWorkingDir.c_str());
    return rc;
}

//Starting point of client threads
static void
serveClient(int sock, sockaddr_in clientAddr)
{
    ssize_t recvBytes = 0;
    struct timeval tv;
    char hdrBuf[CODED_STRM_HDR_LEN];
    char *pBuf = hdrBuf;

    if (sock < 0) {
       return;
    }

    //Don't block forever on reading. Have a timeout
    tv.tv_sec = CLIENT_READ_TIMEOUT;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
              (const char*)&tv, sizeof tv) < 0) {
        int rc = errno;
        cerr << "Error setting recv timeout. client sock/err:"
             << sock << strerror(rc) << std::endl;
        return;
    }

    //create a client specific directory of the form:
    //client_wd_x.x.x.x_yyyy, where x.x.x.x is source ip, and yyyy is source port.
    //e.g. client_wd_10.0.1.1_19834
    clientWorkingDir = "client_wd_" + string(inet_ntoa(clientAddr.sin_addr))
                        + "_" + to_string(clientAddr.sin_port);

    recvBytes = recv(sock, pBuf, CODED_STRM_HDR_LEN, MSG_PEEK);
    if (recvBytes < 0) {
        int rc = errno;
        cerr << "recv() from " << inet_ntoa(clientAddr.sin_addr)
             << " failed with " << rc << std::endl;
    } else if (recvBytes == CODED_STRM_HDR_LEN) {
        if (handleRequest(sock, readHdr(hdrBuf)) != 0) {
            cerr << "Failure processing the request" << std::endl;
        }
    } else {
       cerr << "recv() received fewer than expected(" << recvBytes
            << ") bytes from: " << inet_ntoa(clientAddr.sin_addr)
            << std::endl;
    }
    close(sock);
}

int
main (int argc, char *argv[])
{
    int rc  = success;
    // socket address used to store client address
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);

    // socket address used to store server address
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    int listenSock;
    if ((listenSock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "could not create listen socket" << std::endl;
        rc = failure;
        goto cleanup_and_exit;
    }

    if ((bind(listenSock, (struct sockaddr *)&serverAddr,
                    sizeof(serverAddr))) < 0) {
        cerr << "Bind failure, aborting" << std::endl;
        rc = failure;
        goto cleanup_and_exit;
    }

    if (listen(listenSock, LISTEN_BACKLOG_LIMIT) < 0) {
        cerr << "Listen failure, aborting" << std::endl;
        rc = failure;
        goto cleanup_and_exit;
    }

    while (true) {
        int sock;
        if ((sock = accept(listenSock, (struct sockaddr *)&clientAddr,
                        &clientAddrLen)) < 0) {
            cerr << "Error in accepting client connection" << std::endl;
        }

        cout << "New connection from: " << inet_ntoa(clientAddr.sin_addr)
             << ":" << to_string(clientAddr.sin_port) << std::endl;

        std::thread worker(serveClient, sock, clientAddr);
        worker.detach();
    }

cleanup_and_exit:
    close(listenSock);
    return rc;
}
