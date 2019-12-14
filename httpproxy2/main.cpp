//
//  main.cpp
//  httpproxy2
//
//  Created by WENTAO XING on 2019/12/10.
//  Copyright © 2019 WENTAO XING. All rights reserved.
//

#include "./libproxy.hpp"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

void sig_int(int);

int main(int argc, char ** argv) {
    char * port = NULL, * host = NULL;
    int connfd, listenfd;
    if (argc < 2) oops("Usage: ./proxyserv host port");
    
    iget = iput = 0;
    left = MAXTHREAD;
    
    if (argc == 2) {
        port = argv[1];
    } else {
        host = argv[1];
        port = argv[2];
    }
    
    listenfd = tcp_listen(host, port);
    t_ptr = (Thread *) calloc(MAXTHREAD, sizeof(Thread));
    
    for (int i = 0; i < MAXTHREAD; i++) {
        make_thread(i);
    }
    
    
    signal(SIGINT, sig_int);
    
    for (;;) {
        connfd = accept(listenfd, NULL, NULL);
        if (connfd == -1) continue;
        printf("Receive new connection\n");
        
        Pthread_mutex_lock(&mutex);
        printf("main thread lock mutex\n");
        if (left > 0) {
            connfds[iput] = connfd;
            if (++iput >= MAXSIZE)  iput = 0;
            if (iput == iget) oops("connfd buffer error: ");
            Pthread_cond_signal(&cond);
        } else {
            pthread_t tid;
            int fd = connfd;
            Pthread_create(&tid, NULL, &handle_new_reqest, (void *) &fd);
            Pthread_detach(tid);
        }
        printf("main thread unlock mutex\n");
        Pthread_mutex_unlock(&mutex);
        printf("main thread mutex unlocked\n");
    }
    return 0;
}

void sig_int(int signo) {
    free(t_ptr);
    for (int i = 0; i < MAXTHREAD; i++) {
        printf("thread [%d] served %lu client\n", i, t_ptr[i].count);
    }
    exit(0);
}
