/******************************************************************************
* echo_server.c                                                               *
*                                                                             *
* Description: This file contains the C source code for an echo server.  The  *
*              server runs on a hard-coded port and simply write back anything*
*              sent to it by connected clients.  It does not support          *
*              concurrent clients.                                            *
*                                                                             *
* Authors: Athula Balachandran <abalacha@cs.cmu.edu>,                         *
*          Wolf Richter <wolf@cs.cmu.edu>                                     *
*                                                                             *
*******************************************************************************/

#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <parse.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <pthread.h>  //TO get tid

#include <errno.h>

#define ECHO_PORT 9999
#define BUF_SIZE 8192
#define FILENAME "cgi/CGI/cgi_script.py"

char* ARGV[] = {
                    FILENAME,
                    NULL
               };

char* ENVP[22];

char* POST_BODY = "This is the stdin body...\n";

struct sockaddr_in addr, cli_addr;
void get_header(Request* request, char* target, char* toget) {
    for(int i = 0;i < request->header_count;i++) {
        if(!strcmp(target, request->headers[i].header_name)) {
            strcpy(toget, request->headers[i].header_value);
            return;
        }
    }
    toget[0] = '\0';
    return;
}
int judge_for_cgi(char* ch) {
    int len = strlen(ch);
    for(int i = 0;i < len;i++) {
        if(ch[i] == '?') return i + 1;
    }
    return 0;
}
int work_for_cgi(int sock, int client_sock, Request* request, struct sockaddr_in cli) {
    /*************** BEGIN VARIABLE DECLARATIONS **************/
    pid_t pid;
    int stdin_pipe[2];
    int stdout_pipe[2];
    char buf[BUF_SIZE];
    char htmlbuf[BUF_SIZE];
    int readret;
    /*************** END VARIABLE DECLARATIONS **************/

    /*************** BEGIN PIPE **************/
    /* 0 can be read from, 1 can be written to */
    if (pipe(stdin_pipe) < 0)
    {
        fprintf(stderr, "Error piping for stdin.\n");
        return EXIT_FAILURE;
    }

    if (pipe(stdout_pipe) < 0)
    {
        fprintf(stderr, "Error piping for stdout.\n");
        return EXIT_FAILURE;
    }
    /*************** END PIPE **************/

    /*************** BEGIN FORK **************/
    pid = fork();
    /* not good */
    if (pid < 0)
    {
        fprintf(stderr, "Something really bad happened when fork()ing.\n");
        return EXIT_FAILURE;
    }

    /* child, setup environment, execve */
    if (pid == 0)
    {
        /*************** BEGIN EXECVE ****************/
        close(stdout_pipe[0]);
        close(stdin_pipe[1]);
        dup2(stdout_pipe[1], fileno(stdout));
        dup2(stdin_pipe[0], fileno(stdin));
        /* you should probably do something with stderr */

        /* pretty much no matter what, if it returns bad things happened... */
        char ch[500];
        char setenvp[][500] = {
            "CONTENT_LENGTH=",
            "CONTENT_TYPE=",
            "GATEWAY_INTERFACE=CGI/1.1",
            "PATH_INFO=",
            "QUERY_STRING=",
            "REMOTE_ADDR=",
            "REQUEST_METHOD=",
            "REQUEST_URI=",
            "SCRIPT_NAME=/login.php",
            "SERVER_PORT=9999",
            "SERVER_PROTOCOL=HTTP/1.1",
            "SERVER_SOFTWARE=LISO/1.0",
            "HTTP_ACCEPT=",
            "HTTP_REFERER=",
            "HTTP_ACCEPT_ENCODING=",
            "HTTP_ACCEPT_LANGUAGE=",
            "HTTP_ACCEPT_CHARSET=",
            "HTTP_HOST=",
            "HTTP_COOKIE=",
            "HTTP_USER_AGENT=",
            "HTTP_CONNECTION=",
            NULL
       };
        get_header(request, "CONTENT_LENGTH", ch);
        strcpy(setenvp[0], ch);
        get_header(request, "CONTENT_TYPE", ch);
        strcat(setenvp[1], ch);
        int st = 10, en;
        en = st;
        while(request->http_uri[en] != '?') en++;
        for(int i = 0;i < en - st;i++) ch[i] = request->http_uri[i + st];
        ch[en - st] = 0;
        strcat(setenvp[3], ch);
        strcat(setenvp[4], request->http_uri + en + 1);
        sprintf(ch, "%s", inet_ntoa(cli.sin_addr));
        strcat(setenvp[5], ch);
        strcat(setenvp[6], request->http_method);
        strcat(setenvp[7], request->http_uri);
        get_header(request, "ACCEPT", ch);
        strcat(setenvp[12], ch);
        get_header(request, "REFERER", ch);
        strcat(setenvp[13], ch);
        get_header(request, "ACCEPT_ENCODING", ch);
        strcat(setenvp[14], ch);
        get_header(request, "ACCEPT_LANGUAGE", ch);
        strcat(setenvp[15], ch);
        get_header(request, "ACCEPT_CHARSET", ch);
        strcat(setenvp[16], ch);
        get_header(request, "HOST", ch);
        strcat(setenvp[17], ch);
        get_header(request, "COOKIE", ch);
        strcat(setenvp[18], ch);
        get_header(request, "USER_AGENT", ch);
        strcat(setenvp[19], ch);
        get_header(request, "CONNECTION", ch);
        strcat(setenvp[20], ch);
        for(int i = 0;i < 22;i++) ENVP[i] = setenvp[i];
        if (execve(FILENAME, ARGV, ENVP))
        {
            execve_error_handler();
            fprintf(stderr, "Error executing execve syscall.\n");
            return EXIT_FAILURE;
        }
        /*************** END EXECVE ****************/ 
    }

    if (pid > 0)
    {
        fprintf(stdout, "Parent: Heading to select() loop.\n");
        close(stdout_pipe[1]);
        close(stdin_pipe[0]);

        if (write(stdin_pipe[1], POST_BODY, strlen(POST_BODY)) < 0)
        {
            fprintf(stderr, "Error writing to spawned CGI program.\n");
            return EXIT_FAILURE;
        }

        close(stdin_pipe[1]); /* finished writing to spawn */

        /* you want to be looping with select() telling you when to read */
        while((readret = read(stdout_pipe[0], buf, BUF_SIZE-1)) > 0)
        {
            buf[readret] = '\0'; /* nul-terminate string */
        }
        strcpy(htmlbuf, buf);
        strcpy(buf,  "HTTP/1.1 200 OK\r\n");
        strcat(buf, "Server: liso/1.0\r\n");
        strcat(buf, "Date: ");
        time_t t_liso = time(NULL);
        struct tm* time_liso = gmtime(&t_liso);
        strftime(buf + strlen(buf), 128, "%a, %d %b %Y %X %Z", time_liso);
        strcat(buf + strlen(buf), "\r\n");
        strcat(buf, "Content-Length: ");
        sprintf(buf + strlen(buf), "%ld", strlen(htmlbuf));
        strcat(buf, "\r\n");
        strcat(buf, "Content-Type: text/html\r\n\r\n");
        strcat(buf, htmlbuf);
        fprintf(stdout, "Got from CGI: %s\n", buf);
        int buf_size = strlen(buf) + 1;
        if (send(client_sock, buf, buf_size, 0) != buf_size)
        {
            close_socket(client_sock);
            close_socket(sock);
            fprintf(stderr, "Error sending to client.\n");
            return EXIT_FAILURE;
        }
        close(stdout_pipe[0]);
        close(stdin_pipe[1]);

        if (readret == 0)
        {
            fprintf(stdout, "CGI spawned process returned with EOF as \
expected.\n");
            return EXIT_SUCCESS;
        }
    }
    /*************** END FORK **************/

    fprintf(stderr, "Process exiting, badly...how did we get here!?\n");
    return EXIT_FAILURE;
}
void execve_error_handler()
{
    switch (errno)
    {
        case E2BIG:
            fprintf(stderr, "The total number of bytes in the environment \
(envp) and argument list (argv) is too large.\n");
            return;
        case EACCES:
            fprintf(stderr, "Execute permission is denied for the file or a \
script or ELF interpreter.\n");
            return;
        case EFAULT:
            fprintf(stderr, "filename points outside your accessible address \
space.\n");
            return;
        case EINVAL:
            fprintf(stderr, "An ELF executable had more than one PT_INTERP \
segment (i.e., tried to name more than one \
interpreter).\n");
            return;
        case EIO:
            fprintf(stderr, "An I/O error occurred.\n");
            return;
        case EISDIR:
            fprintf(stderr, "An ELF interpreter was a directory.\n");
            return;
        case ELIBBAD:
            fprintf(stderr, "An ELF interpreter was not in a recognised \
format.\n");
            return;
        case ELOOP:
            fprintf(stderr, "Too many symbolic links were encountered in \
resolving filename or the name of a script \
or ELF interpreter.\n");
            return;
        case EMFILE:
            fprintf(stderr, "The process has the maximum number of files \
open.\n");
            return;
        case ENAMETOOLONG:
            fprintf(stderr, "filename is too long.\n");
            return;
        case ENFILE:
            fprintf(stderr, "The system limit on the total number of open \
files has been reached.\n");
            return;
        case ENOENT:
            fprintf(stderr, "The file filename or a script or ELF interpreter \
does not exist, or a shared library needed for \
file or interpreter cannot be found.\n");
            return;
        case ENOEXEC:
            fprintf(stderr, "An executable is not in a recognised format, is \
for the wrong architecture, or has some other \
format error that means it cannot be \
executed.\n");
            return;
        case ENOMEM:
            fprintf(stderr, "Insufficient kernel memory was available.\n");
            return;
        case ENOTDIR:
            fprintf(stderr, "A component of the path prefix of filename or a \
script or ELF interpreter is not a directory.\n");
            return;
        case EPERM:
            fprintf(stderr, "The file system is mounted nosuid, the user is \
not the superuser, and the file has an SUID or \
SGID bit set.\n");
            return;
        case ETXTBSY:
            fprintf(stderr, "Executable was open for writing by one or more \
processes.\n");
            return;
        default:
            fprintf(stderr, "Unkown error occurred with execve().\n");
            return;
    }
}
int close_socket(int sock)
{
    if (close(sock))
    {
        fprintf(stderr, "Failed closing socket.\n");
        return 1;
    }
    return 0;
}
void write2log_error(pid_t pid_now, struct sockaddr_in cli, pthread_t tid, char* error_message) {
    char tmp[200];
    FILE* fp;
    time_t t_liso = time(NULL);
    struct tm* time_liso = gmtime(&t_liso);
    if((fp = fopen("./log/log.txt", "a")) == NULL) {
        printf("fail to open the file\n");
        return;
    }
    strftime(tmp, 128, "[%a %b %d %X %Y] ", time_liso);
    sprintf(tmp + strlen(tmp), "[core:error] [pid %d:tid %ld] [client %s] %s\r\n", pid_now, tid, inet_ntoa(cli.sin_addr), error_message);
    fputs(tmp, fp);
    fclose(fp);
}
void write2log_access(struct sockaddr_in cli, Request* request, char* status_code, long int sz) {
    char tmp[200];
    FILE* fp;
    if((fp = fopen("./log/log.txt", "a")) == NULL) {
        printf("fail to open the file\n");
        return;
    }
    time_t t_liso = time(NULL);
    struct tm* time_liso = gmtime(&t_liso);
    sprintf(tmp, "%s - - ", inet_ntoa(cli.sin_addr));
    strftime(tmp + strlen(tmp), 128, "[%d/%b/%Y:%X %Z] ", time_liso);
    sprintf(tmp + strlen(tmp), "\"%s ./static_site%sindex.html %s\" %s ", request->http_method, request->http_uri, request->http_version, status_code);
    if(sz > 0) sprintf(tmp + strlen(tmp), "%ld\r\n", sz);
    else strcat(tmp, "-\r\n");
    fputs(tmp, fp);
    fclose(fp);
}
void seek_for_type(char* now, char* type) {
    int len = strlen(now);
    for(int i = 1;i < len;i++) {
        if(now[i] == '.') {
            if(!strcmp(now + i + 1, "html")) strcpy(type, "text/html");
            else if(!strcmp(now + i + 1, "css")) strcpy(type, "text/css");
            else if(!strcmp(now + i + 1, "png")) strcpy(type, "image/png");
            else if(!strcmp(now + i + 1, "jpeg")) strcpy(type, "image/jpeg");
            else if(!strcmp(now + i + 1, "gif")) strcpy(type, "image/gif");
            else strcpy(type, "unknown");
            return;
        }
    }
    strcpy(type, "unknown");
}
int cal(int x) {
    int ans = 0;
    while(x) {
        ans++;
        x /= 10;
    }
    return ans;
}
void rev_length(char* buf, int pos) {
    int buflen = strlen(buf) - 5 + 1, len;
    len = cal(buflen) + (cal(buflen) != cal(buflen + cal(buflen)));
    buflen += len;
    for(int i = pos + len - 1;i >= pos;i--) {
        buf[i] = '0' + buflen % 10;
        buflen /= 10;
    }
    strcpy(buf + pos + len, buf + pos + 5);
}
int handle_connection(int sock, int client_sock) {
    ssize_t readret;
    char buf[BUF_SIZE];
    char bufrev[1];
    readret = 0;
    int now = 0, len = 0;
    memset(buf, 0, sizeof buf);
    while(recv(client_sock, bufrev, 1, 0) >= 1){
        buf[len++] = bufrev[0];
        if(len == 1 && buf[0] == '\r') {
            while(recv(client_sock, buf, BUF_SIZE, MSG_DONTWAIT) >= 1);
            break;
        }
        if(len == BUF_SIZE) {
            strcpy(buf, "HTTP/1.1 400 Bad request\r\n\r\n");
            while(recv(client_sock, buf, BUF_SIZE, MSG_DONTWAIT) >= 1);
            write2log_error(getpid(), cli_addr, pthread_self(), "HTTP/1.1 400 Bad request");
            break;
        }
        if((now == 0 || now == 2) && bufrev[0] == '\r') now++;
        else if((now == 1 || now == 3) && bufrev[0] == '\n') now++;
        else now = 0;
        if(now != 4) continue;
        readret = len;
        len = now = 0;
        Request *request = parse(buf, readret, client_sock);
        if(!request) {
            strcpy(buf, "HTTP/1.1 400 Bad request\r\n\r\n");
            write2log_error(getpid(), cli_addr, pthread_self(), "HTTP/1.1 400 Bad request");
        } else if(strcmp(request->http_method, "GET") && strcmp(request->http_method, "POST") && strcmp(request->http_method, "HEAD")) {
            strcpy(buf, "HTTP/1.1 501 Not Implemented\r\n\r\n");
            write2log_error(getpid(), cli_addr, pthread_self(), "HTTP/1.1 501 Not Implemented");
        } else if(strcmp(request->http_version, "HTTP/1.1")) {
            strcpy(buf, "HTTP/1.1 505 HTTP Version not supported\r\n\r\n");
            write2log_error(getpid(), cli_addr, pthread_self(), "HTTP/1.1 505 HTTP Version not supported");
        } else if(!strcmp(request->http_method, "GET") && judge_for_cgi(request->http_uri)) {
            if(work_for_cgi(sock, client_sock, request, cli_addr)) {
                strcpy(buf, "HTTP/1.1 500 Internal Server Error\r\n\r\n");
            }
        } else if(strcmp(request->http_method, "POST")){
                char file_path[200] = "./static_site";
                strcat(file_path, request->http_uri);
                strcat(file_path, "index.html");
                strcpy(buf,  "HTTP/1.1 200 OK\r\n");
                int flg = 1;
                //server
                strcat(buf, "Server: liso/1.0\r\n");
                //date
                strcat(buf, "Date: ");
                time_t t_liso = time(NULL);
                struct tm* time_liso = gmtime(&t_liso);
                strftime(buf + strlen(buf), 128, "%a, %d %b %Y %X %Z", time_liso);
                strcat(buf + strlen(buf), "\r\n");
                //content-length
                struct stat* mystat = (struct stat*)malloc(sizeof(struct stat));
                if(stat(file_path, mystat) < 0) {
                    strcpy(buf,  "HTTP/1.1 404 Not Found\r\n\r\n");
                    flg = 0;
                    write2log_error(getpid(), cli_addr, pthread_self(), "HTTP/1.1 404 Not Found");
                }
                if(flg) {
                    long int len = (strcmp(request->http_method, "GET")) ? 0 : mystat->st_size;
                    write2log_access(cli_addr, request, "200", len);
                    strcat(buf, "Content-Length: ");
                    sprintf(buf + strlen(buf), "%ld", mystat->st_size);
                    strcat(buf, "\r\n");
                    //content-type
                    char tmp[200];
                    strcat(buf, "Content-Type: ");
                    seek_for_type(file_path, tmp);
                    strcat(buf, tmp);
                    strcat(buf, "\r\n");
                    //last-modified
                    strcat(buf, "Last-Modified: ");
                    t_liso = mystat->st_mtime;
                    time_liso = gmtime(&t_liso);
                    strftime(buf + strlen(buf), 128, "%a, %d %b %Y %X %Z", time_liso);
                    strcat(buf + strlen(buf), "\r\n");
                    free(mystat);
                    //connection
                    get_header(request, "Connection", tmp);
                    strcat(buf, "Connection: ");
                    strcat(buf, tmp);
                    strcat(buf, "\r\n\r\n");
                }
                if(flg && !strcmp(request->http_method, "GET")) {
                    int fd_in = open(file_path, O_RDONLY);
                    readret += read(fd_in, buf + strlen(buf), BUF_SIZE);
                }
            } else {
                write2log_access(cli_addr, request, "200", 0);
                }
        if(request) {
            free(request->headers);
            free(request);
        }
        readret = strlen(buf);
        if (readret > 0 && send(client_sock, buf, readret, 0) != readret)
        {
            close_socket(client_sock);
            close_socket(sock);
            fprintf(stderr, "Error sending to client.\n");
            return EXIT_FAILURE;
        }
        memset(buf, 0, BUF_SIZE);
    }
    if (readret == -1) {
        close_socket(client_sock);
        close_socket(sock);
        fprintf(stderr, "Error reading from client socket.\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
void set_fl(int fd, int to_set) {
    int flags = fcntl(fd, F_GETFL);
    if(flags & to_set) return;
    fcntl(fd, F_SETFL, flags ^ to_set);
}
void clr_fl(int fd, int to_clr) {
    int flags = fcntl(fd, F_GETFL);
    if(!(flags & to_clr)) return;
    fcntl(fd, F_SETFL, flags ^ to_clr);
}
int main(int argc, char* argv[])
{
    int sock, client_sock;
    socklen_t cli_size;
    cli_size = sizeof(cli_addr);

    fprintf(stdout, "----- Liso Server -----\n");
    
    /* all networked programs must create a socket */
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        fprintf(stderr, "Failed creating socket.\n");
        return EXIT_FAILURE;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(ECHO_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* servers bind sockets to ports---notify the OS they accept connections */
    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)))
    {
        close_socket(sock);
        fprintf(stderr, "Failed binding socket.\n");
        return EXIT_FAILURE;
    }


    if (listen(sock, 5))
    {
        close_socket(sock);
        fprintf(stderr, "Error listening on socket.\n");
        return EXIT_FAILURE;
    }

    fd_set current_sockets, ready_sockets;
    FD_ZERO(&current_sockets);
    FD_SET(sock, &current_sockets);
    /* finally, loop waiting for input and then write it back */
    while (1)
    {
        ready_sockets = current_sockets;
        int ready_num = select(FD_SETSIZE, &ready_sockets, NULL, NULL, NULL);
        if(ready_num < 0) {
            fprintf(stderr, "Error select.\n");
            return EXIT_FAILURE;
        }
        for(int i = 0;i < FD_SETSIZE;i++) {
            if(FD_ISSET(i, &ready_sockets)) {
                if(i == sock) {
                    if ((client_sock = accept(sock, (struct sockaddr *) &cli_addr, &cli_size)) == -1) {
                        close(sock);
                        fprintf(stderr, "Error accepting connection.\n");
                    }
                    FD_SET(client_sock, &current_sockets);
                } else {
                    set_fl(i, O_NONBLOCK);
                    handle_connection(sock, i);
                    clr_fl(i, O_NONBLOCK);
                    FD_CLR(i, &current_sockets);
                    if(close_socket(i)) fprintf(stderr, "Error closing client socket.\n");
                }
            }
        }
        
    }
    close_socket(sock);
    return EXIT_SUCCESS;
}

