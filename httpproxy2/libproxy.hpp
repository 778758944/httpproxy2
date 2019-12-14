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

#include <map>
#include <vector>
#include <string>

#define MAXTHREAD 25
#define MAXSIZE 50

typedef struct FLink{
    bool isPedding;
    int fd;
    FLink(bool _isPedding, bool _fd): isPedding(_isPedding), fd(_fd) {};
} FLink;

typedef struct {
    pthread_t tid;
    unsigned long count;
} Thread;

extern int iget, iput, left, connfds[MAXSIZE];
extern Thread * t_ptr;
extern pthread_cond_t cond;

extern pthread_mutex_t mutex;
extern int maxfd;
extern fd_set allset;
extern std::map<std::string, std::vector<FLink *> > links;

void * handle_new_reqest(void * p);
void make_thread(int n);

#endif /* libproxy_hpp */
