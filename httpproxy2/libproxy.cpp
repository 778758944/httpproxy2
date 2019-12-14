//
//  libproxy.cpp
//  httpproxy2
//
//  Created by WENTAO XING on 2019/12/10.
//  Copyright © 2019 WENTAO XING. All rights reserved.
//

#include "libproxy.hpp"

int maxfd;
fd_set allset;
std::map<std::string, std::vector<FLink *> > links;
int iget, iput, left, connfds[MAXSIZE];
Thread * t_ptr;



void http_proxy(int connfd, char * domain, char * port, char * reqLine,  int isHttps);
void blind_proxy(const int connfd, const char * domain, const char * port, char * reqLine);
void * pthread_proxy_handler(void * p);


void * handle_new_reqest(void * p) {
    int connfd = *((int *) p);
    
    int isHttps = 0;
    ssize_t nread;
    char domain[256],
         port[10],
         method[10],
         *reqLine,
         *buf;
    
    buf = (char *) malloc(URISIZE);
    
    if ((nread = read_line(connfd, buf, URISIZE - 1)) > 0) {
        reqLine = parser_req_line(buf, domain, port, method);
        free(buf);
        
        if (strcmp(method, "CONNECT") == 0) {
            isHttps = 1;
            char connectRes[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
            char * readBuf = (char *) malloc(BUFSIZ * 100);
            write(connfd, connectRes, strlen(connectRes));
            read(connfd, readBuf, BUFSIZ);
            free(readBuf);
        }
        
        if ((isHttps == 1 && isProxyHost(domain) == 1) || isHttps == 0) {
            // https
        } else {
            blind_proxy(connfd, domain, port, reqLine);
        }
    }
    return NULL;
}

void make_thread(int n) {
    pthread_t t_id;
    Pthread_create(&t_id, NULL, &pthread_proxy_handler, (void *) &n);
    t_ptr[n].tid = t_id;
    return;
}

void blind_proxy(const int connfd, const char * domain, const char * port, char * reqLine) {
    int ori_fd, maxfd, ns;
    fd_set allset, rset;
    ssize_t nread;
    char buf[BUFSIZ];
    
    ori_fd = tcp_connect(domain, port);
    if (ori_fd == -1) return;
    if (reqLine != NULL) write(ori_fd, reqLine, strlen(reqLine));
    free(reqLine);
    
    FD_ZERO(&allset);
    FD_SET(connfd, &allset);
    FD_SET(ori_fd, &allset);
    
    maxfd = ori_fd > connfd ? ori_fd + 1 : connfd + 1;
    
    for (;;) {
        rset = allset;
        ns = select(maxfd, &rset, NULL, NULL, NULL);
        if (ns == -1) break;
        
        if (FD_ISSET(connfd, &rset)) {
            nread = read(connfd, buf, BUFSIZ);
            if (nread < 0) {
                perror("read proxy conn: ");
                break;
            } else if (nread == 0) {
                close(connfd);
                close(ori_fd);
                break;
            } else {
                write(ori_fd, buf, nread);
            }
        }
        
        if (FD_ISSET(ori_fd, &rset)) {
            nread = read(ori_fd, buf, BUFSIZ);
            if (nread < 0) {
                perror("read origin serv: ");
                break;
            } else if (nread == 0) {
                close(ori_fd);
                close(connfd);
                break;
            } else {
                write(connfd, buf, nread);
            }
        }
    }
}


void * pthread_proxy_handler(void * p) {
    int index = * ((int *) p);
    int connfd;
    Pthread_detach(pthread_self());
    for (;;) {
        Pthread_mutex_lock(&mutex);
        printf("pthread[%d] lock mutex\n", index);
        while(iget == iput) {
            // stop process and unlock mutex
            printf("pthread[%d] release mutex and sleep\n", index);
            Pthread_cond_wait(&cond, &mutex);
            printf("pthread[%d] signal\n", index);
        }
        
        connfd = connfds[iget];
        left--;
        
        t_ptr[index].count++;
        if (++iget == MAXSIZE) iget = 0;
        Pthread_mutex_unlock(&mutex);
        
        printf("pthread[%d] unlock mutex to handle request\n", index);
        handle_new_reqest((void *) &connfd);
        
        printf("pthread[%d] prepare to lock mutex for left\n", index);
        Pthread_mutex_lock(&mutex);
        printf("pthread[%d] lock mutex to add left\n", index);
        left++;
        Pthread_mutex_unlock(&mutex);
        printf("pthread[%d] unlock mutex after left\n", index);
        
    }
    return NULL;
}


void http_proxy(int connfd, char * domain, char * port, char * reqLine,  int isHttps) {
    char protocol[10];
    if (isHttps == 1) {
        strcpy(protocol, "https");
    } else {
        strcpy(protocol, "http");
    }
    fd_set sset, rrset;
    std::vector<int> fds;
    
    if (reqLine != NULL) {
        const char * matchUrl = isMatch(reqLine, domain, protocol, port);
        
    }
}
