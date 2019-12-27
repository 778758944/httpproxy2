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
std::unordered_map<std::string, std::vector<FLink *> > links;
int iget, iput, left, connfds[MAXSIZE];
Thread * t_ptr;



void http_proxy(int connfd, char * domain, char * port, char * reqLine);
void blind_proxy(const int connfd, const char * domain, const char * port, char * reqLine);
void * pthread_proxy_handler(void * p);
FLink * match_helper(char * buf, char * domain, char * port, const char * protocol, std::unordered_map<std::string, FLink *> &m);
void free_flink(FLink * link);
int write_to_link(FLink * link, char * buf, int size);
void read_res(FLink * curLink, FLink * lastLink, std::unordered_map<std::string, FLink *> &fds, fd_set * rset, fd_set * allset, int n);
int read_link(FLink * curLink, FLink * link, fd_set *rset, fd_set *allset, std::unordered_map<std::string, FLink *> &fds);
REQUEST_STATUS send_request(char * buf, ssize_t nbytes, char * domain, char * port, const char * protocol, fd_set * sset, FLink ** lastLink, int * maxfd, REQUEST_STATUS status, long * bodySize, std::unordered_map<std::string, FLink *> &fds);


void free_flink(FLink * link) {
    if (link == NULL) return;
    if (link->ssl != NULL) SSL_free(link->ssl);
    if (link->io != NULL) BIO_free(link->io);
    free(link);
}


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
        if (strlen(method) == 0) {
            free(buf);
            return NULL;
        }
        
        if (strcmp(method, "CONNECT") == 0) {
            isHttps = 1;
            char connectRes[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
            write(connfd, connectRes, strlen(connectRes));
            read(connfd, buf, BUFSIZ);
        }
        
        free(buf);
        
        if (isHttps == 0 || (isHttps == 1 && isProxyHost(domain) == 1)) {
            http_proxy(connfd, domain, port, reqLine);
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
        while(iget == iput) {
            Pthread_cond_wait(&cond, &mutex);
        }
        printf("Thread[%d]: start\n", index);
        connfd = connfds[iget];
        left--;
        
        t_ptr[index].count++;
        if (++iget == MAXSIZE) iget = 0;
        Pthread_mutex_unlock(&mutex);
        handle_new_reqest((void *) &connfd);
        Pthread_mutex_lock(&mutex);
        left++;
        Pthread_mutex_unlock(&mutex);
        printf("Thread[%d]: exit\n", index);
    }
    return NULL;
}


void http_proxy(int connfd, char * domain, char * port, char * reqLine) {
    printf("connect to %s:%s\n", domain, port);
    fd_set sset, rrset;
    std::unordered_map<std::string, FLink *> fds;
    ssize_t nbytes;
    const char * protocol = reqLine == NULL ? "https" : "http";
    int n, maxfd, orifd;
    char buf[URISIZE];
    FLink * lastLink, * mainLink;
    REQUEST_STATUS status = DONE;
    ssize_t bodySize = 0;
    
    SSL * ssl = NULL, * cssl;
    BIO * io, * cio;
    RSA * rsa = nullptr;
    
    if (strcmp(protocol, "https") == 0) {
        // https server
        ssl = SSL_new(ctx);
        BIO * sbio = BIO_new_socket(connfd, BIO_NOCLOSE);
        SSL_set_bio(ssl, sbio, sbio);
        io = BIO_new(BIO_f_buffer());
        BIO * ssl_bio = BIO_new(BIO_f_ssl());
        BIO_set_ssl(ssl_bio, ssl, BIO_NOCLOSE);
        BIO_push(io, ssl_bio);
//        BIO_free(sbio);
//        BIO_free(ssl_bio);
        mainLink = new FLink(false, false, connfd, ssl, io);
        
        // connect to original server
        orifd = tcp_connect(domain, port);
        cssl = SSL_new(ctx);
        cio = BIO_new(BIO_f_buffer());
        BIO * cbio = BIO_new_socket(orifd, BIO_NOCLOSE);
        SSL_set_bio(cssl, cbio, cbio);
        BIO * cssl_bio = BIO_new(BIO_f_ssl());
        BIO_set_ssl(cssl_bio, cssl, BIO_NOCLOSE);
        BIO_push(cio, cssl_bio);
        
        if (SSL_connect(cssl) < 0) {
            ERR_print_errors_fp(stdout);
            return;
        }
        
        
        X509 * cert = SSL_get_peer_certificate(cssl);
        rsa = resignCertificate(cert, ssl);
        
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stdout);
            RSA_free(rsa);
            return;
        }
        
        lastLink = new FLink(false, false, orifd, cssl, cio);
        
        char c_key[300];
        snprintf(c_key, 299, "%s:%s", domain, port);
        std::string key(c_key);
        strcpy(lastLink->key, c_key);
        fds[key] = lastLink;
        
        
        FD_ZERO(&sset);
        FD_SET(connfd, &sset);
        FD_SET(orifd, &sset);
        maxfd = connfd > orifd ? connfd + 1 : orifd + 1;
    } else {
        lastLink = match_helper(reqLine, domain, port, protocol, fds);
        free(reqLine);
        if (lastLink == NULL) return;
        status = READ_HEAD;
        
        FD_ZERO(&sset);
        FD_SET(connfd, &sset);
        FD_SET(lastLink->fd, &sset);
        
        FD_SET(lastLink->fd, &sset);
        maxfd = connfd > lastLink->fd ? connfd + 1 : lastLink->fd + 1;
        mainLink = new FLink(0, 0, connfd);
    }
    
    for (;;) {
        rrset = sset;
        n = select(maxfd, &rrset, NULL, NULL, NULL);
        if (n < 0) {
            perror("select err: ");
            return;
        }
        
        if (FD_ISSET(connfd, &rrset)) {
            if (strcmp(protocol, "https") == 0 && ssl != NULL) {
                do {
                    if (status == READ_BODY) {
                        nbytes = SSL_read(ssl, buf, URISIZE);
                    } else {
                        nbytes = read_ssl_line(ssl, buf, URISIZE - 1);
                    }
                    
                    switch(SSL_get_error(ssl, (int) nbytes)) {
                        case SSL_ERROR_NONE:
                            status = send_request(buf, nbytes, domain, port, protocol, &sset, &lastLink, &maxfd, status, &bodySize, fds);
                            if (status == FAILED) return;
                            break;
                            
                        case SSL_ERROR_ZERO_RETURN:
                            for (std::pair<const std::string, FLink *> &p: fds) {
                                FLink * curLink = p.second;
                                if (curLink == NULL) break;
                                if (curLink->ssl != NULL) {
                                    SSL_shutdown(curLink->ssl);
                                } else {
                                    close(curLink->fd);
                                }
                                fds.erase(p.first);
                                free_flink(curLink);
                            }
                            SSL_shutdown(ssl);
                            free(mainLink);
                            RSA_free(rsa);
                            return;
                            break;
                            
                        default:
                            ERR_print_errors_fp(stdout);
                            RSA_free(rsa);
                            return;
                    }
                } while (SSL_pending(ssl));
                
            } else {
                // http send request
                if (status == READ_BODY) {
                    nbytes = read(connfd, buf, URISIZE);
                } else {
                    nbytes = read_line(connfd, buf, URISIZE - 1);
                }
                if (nbytes < 0) {
                    perror("read connfd err:");
                    // freebuf
                    return;
                } else if (nbytes == 0) {
                    printf("disconnected %s:%s\n", domain, port);
                    for (std::pair<const std::string, FLink *> &p: fds) {
                        FLink * curLink = p.second;
                        if (curLink == NULL) break;
                        if (curLink->ssl != NULL) {
                            SSL_shutdown(curLink->ssl);
                        } else {
                            close(curLink->fd);
                        }
                        fds.erase(p.first);
                        free_flink(curLink);
                    }
                    free_flink(mainLink);
                    close(connfd);
                    return;
                } else {
                    status = send_request(buf, nbytes, domain, port, protocol, &sset, &lastLink, &maxfd, status, &bodySize, fds);
                    if (status == FAILED) return;
                }
            }
            n--;
        }
        
        if (n > 0) {
            if (FD_ISSET(lastLink->fd, &rrset)) {
                read_link(mainLink, lastLink, &rrset, &sset, fds);
                n--;
            }
        }
        
        if (n > 0) {
            read_res(mainLink, lastLink, fds, &rrset, &sset, n);
        }
    }
}


FLink * match_helper(char * buf, char * domain, char * port, const char * protocol, std::unordered_map<std::string, FLink *> &m) {
    int fd;
    FLink * link;
    const char * matchUrl = isMatch(buf, domain, protocol, port);
    char c_key[300],
         * f_domain,
         * f_port,
         * reqLine;
    
    if (matchUrl == NULL) {
        f_domain = domain;
        f_port = port;
        reqLine = buf;
    } else {
        f_domain = (char *) malloc(256);
        f_port = (char *) malloc(10);
        char method[10],
             url[URISIZE];
        
        char * s1 = strchr(buf, ' ');
        *s1 = '\0';
        char * s2 = strchr(s1 + 1, ' ') + 1;
        snprintf(url, URISIZE, "%s %s %s", buf, matchUrl, s2);
        reqLine = parser_req_line(url, f_domain, f_port, method);
    }
    
    snprintf(c_key, 299, "%s:%s", f_domain, f_port);
    std::string key(c_key);
    
    if (m.count(key) > 0) {
        link = m[key];
    } else {
        fd = tcp_connect(f_domain, f_port);
        if (fd == -1) return NULL;
        link = (FLink *) malloc(sizeof(FLink));
        link->isPedding = true;
        link->isProxy = matchUrl == NULL ? false : true;
        link->fd = fd;
        link->ssl = NULL;
        link->io = NULL;
        strcpy(link->key, c_key);
        
        if (
            (matchUrl == NULL && strncmp(protocol, "https", 5) == 0) ||
            (matchUrl != NULL && strncmp(matchUrl, "https", 5) == 0)
        ) {
            SSL * ssl = SSL_new(ctx);
            BIO * sbio = BIO_new_socket(fd, BIO_NOCLOSE);
            SSL_set_bio(ssl, sbio, sbio);
            
            BIO * io = BIO_new(BIO_f_buffer());
            BIO * ssl_bio = BIO_new(BIO_f_ssl());
            BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);
            BIO_push(io, ssl_bio);
            
            link->ssl = ssl;
            link->io = io;
            
            SSL_connect(ssl);
            
//            BIO_free(sbio);
//            BIO_free(ssl_bio);
        }
        m[key] = link;
    }
    
    write_to_link(link, reqLine, (int) strlen(reqLine));
    
    if (matchUrl != NULL) {
        free(f_domain);
        free(f_port);
        free(reqLine);
    }
    
    return link;
}

int read_link(FLink * curLink, FLink * link, fd_set *rset, fd_set *allset, std::unordered_map<std::string, FLink *> &fds) {
    int fd, nbytes, r;
    char buf[BUFSIZ];
    std::string key(link->key);
    
    if (link->ssl == NULL) {
        fd = link->fd;
        nbytes = (int) read(fd, buf, BUFSIZ);
        if (nbytes < 0) {
            perror("read res error:");
            FD_CLR(fd, allset);
            fds.erase(key);
            free_flink(link);
        } else if (nbytes == 0) {
            close(fd);
            FD_CLR(fd, allset);
            fds.erase(key);
            free_flink(link);
        } else {
            write_to_link(curLink, buf, nbytes);
        }
        r = nbytes;
    } else {
        SSL * ssl = link->ssl;
        do {
            nbytes = SSL_read(ssl, buf, BUFSIZ);
            r = nbytes;
            
            switch(SSL_get_error(ssl, nbytes)) {
                case SSL_ERROR_NONE:
                    write_to_link(curLink, buf, nbytes);
                    break;
                    
                case SSL_ERROR_ZERO_RETURN:
                    SSL_shutdown(ssl);
                    FD_CLR(link->fd, allset);
                    fds.erase(key);
                    free_flink(link);
                    r = 0;
                    return r;
                    break;
                    
                default:
                    ERR_print_errors_fp(stdout);
                    FD_CLR(link->fd, allset);
                    fds.erase(key);
                    free_flink(link);
                    r = -1;
                    return r;
                    break;
            }
        } while (SSL_pending(ssl));
    }
    
    return r;
}

void read_res(FLink * curLink, FLink * lastLink, std::unordered_map<std::string, FLink *> &fds, fd_set * rset, fd_set * allset, int n) {
    for (std::pair<const std::string, FLink *> &p: fds) {
        FLink * link = p.second;
        if (link == lastLink) continue;
        if (FD_ISSET(link->fd, rset)) {
            read_link(curLink, link, rset, allset, fds);
            if (--n == 0) break;
        }
    }
}

int write_to_link(FLink * link, char * buf, int size) {
    if (link->ssl == NULL) {
        return (int) write(link->fd, buf, size);
    } else {
        return SSL_write(link->ssl, buf, size);
    }
}

REQUEST_STATUS send_request(char * buf, ssize_t nbytes, char * domain, char * port, const char * protocol, fd_set * sset, FLink ** lastLink, int * maxfd, REQUEST_STATUS status, long * bodySize, std::unordered_map<std::string, FLink *> &fds) {
    if (status == DONE) {
        nbytes = parser_req_path(buf, nbytes);
        *lastLink = match_helper(buf, domain, port, protocol, fds);
        if (*lastLink == NULL) return FAILED;
        if (!FD_ISSET((*lastLink)->fd, sset)) {
            FD_SET((*lastLink)->fd, sset);
            *maxfd = *maxfd > (*lastLink)->fd + 1 ? *maxfd : (*lastLink)->fd + 1;
        }
        status = READ_HEAD;
    } else if (status == READ_HEAD) {
        char * host = strstr(buf, "Host:");
        if ((*lastLink)->isProxy && host == buf) {
            char newHost[300];
            snprintf(newHost, 299, "Host: %s\r\n", (*lastLink)->key);
            write_to_link(*lastLink, newHost, (int) strlen(newHost));
        } else {
            char * content = strstr(buf, "Content-Length: ");
            if (content == buf) {
                *bodySize = strtol(buf + 15, NULL, 10);
            }
            
            if (strcmp("\r\n", buf) == 0) {
                if (*bodySize == 0) status = DONE;
                else status = READ_HEAD;
            }
            write_to_link(*lastLink, buf, (int) nbytes);
        }
    } else {
        *bodySize = (long) (*bodySize - nbytes);
        if (*bodySize == 0) status = DONE;
        write_to_link(*lastLink, buf, (int) nbytes);
    }
    
    return status;
}
