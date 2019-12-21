//
//  libproxy.hpp
//  httpproxy2
//
//  Created by WENTAO XING on 2019/12/10.
//  Copyright © 2019 WENTAO XING. All rights reserved.
//

#ifndef libproxy_hpp
#define libproxy_hpp
#include "./libnet.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>

#define MAXTHREAD 25
#define MAXSIZE 50

typedef struct {
    pthread_t tid;
    unsigned long count;
} Thread;

typedef struct FLink {
    bool isProxy;
    bool isPedding;
    int fd;
    SSL * ssl;
    BIO * io;
    char key[300];
    FLink(bool _isProxy, bool _isPedding, int _fd): isProxy(_isProxy), isPedding(_isPedding), fd(_fd), ssl(NULL), io(NULL) {};
    FLink(bool _isProxy, bool _isPedding, int _fd, SSL * _ssl, BIO * _io): isProxy(_isProxy), isPedding(_isPedding), fd(_fd), ssl(_ssl), io(_io) {};
} FLink;

enum REQUEST_STATUS {
    DONE = 0,
    READ_HEAD = 1,
    READ_BODY = 2,
    FAILED = 3
};

extern int iget, iput, left, connfds[MAXSIZE];
extern Thread * t_ptr;
extern pthread_cond_t cond;

extern pthread_mutex_t mutex;
extern int maxfd;
extern fd_set allset;
extern std::unordered_map<std::string, std::vector<FLink *> > links;

void * handle_new_reqest(void * p);
void make_thread(int n);

#endif /* libproxy_hpp */
