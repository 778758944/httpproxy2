//
//  libproxy.hpp
//  httpproxy2
//
//  Created by WENTAO XING on 2019/12/10.
//  Copyright © 2019 WENTAO XING. All rights reserved.
//

#ifndef libnet_hpp
#define libnet_hpp

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#define oops(m) { perror(m); exit(-1);}
#define MAPSIZE 6
#define HOSTSIZE 6
#define HTTP_METHOD_SIZE 9
#define URISIZE BUFSIZ * 3
#define HTTP_METHOD_MAX_LENGTH 7

ssize_t read_line(int fd, char * buf, ssize_t n);
int tcp_connect(const char * domain, const char * port);
int tcp_listen(const char * domain, const char * port);
const char * isMatch(char * req_line, char * domain, const char * protocol, char * port);
int isProxyHost(char * host);

// ssl
SSL_CTX * initialize_ctx();
void check_cert(SSL * ssl, char * domain);
int read_ssl_line(SSL * ssl, char * buf, size_t n);
void createCertificate(char * domain, SSL * ssl);
RSA * resignCertificate(X509 * cert, SSL * ssl);

// http
int http_request(const char * url);
char * parser_req_line(char * reqLine, char * domain, char * port, char * method);
ssize_t parser_req_path(char * buf, ssize_t nbytes);
int is_req_line(char * buf);

// pthread
void Pthread_mutex_lock(pthread_mutex_t * mutex);
void Pthread_mutex_unlock(pthread_mutex_t * mutex);
void Pthread_cond_signal(pthread_cond_t * cond);
void Pthread_cond_wait(pthread_cond_t * cond, pthread_mutex_t * mutex);
void Pthread_create(pthread_t * t, const pthread_attr_t * attr,  void *(*start_routine)(void *), void * arg);
void Pthread_detach(pthread_t t);

// SSL GLOBAL VARIABLE
extern SSL_CTX * ctx;

#endif /* libproxy_hpp */
