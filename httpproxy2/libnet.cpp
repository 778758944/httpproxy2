//
//  libproxy.cpp
//  httpproxy2
//
//  Created by WENTAO XING on 2019/12/10.
//  Copyright © 2019 WENTAO XING. All rights reserved.
//

#include "libnet.hpp"

const char PROXY_SOUR[][BUFSIZ] = {
    "https://devmpop.zoomdev.us/index.js",
    "https://devmpop.zoomdev.us/index.css",
    "https://devepmpop.zoomdev.us/index.js",
    "https://devepmpop.zoomdev.us/index.css",
    "https://marketplaceop.zoom.us/index.js",
    "https://marketplaceop.zoom.us/index.css",
    "http://www.erji.net/image/wind/erjix.jpg",
};

const char PROXY_DEST[][BUFSIZ] = {
    "http://localhost:9000/index.js",
    "http://localhost:9000/index.css",
    "http://localhost:9000/index.js",
    "http://localhost:9000/index.css",
    "http://localhost:9000/index.js",
    "http://localhost:9000/index.css",
    "http://www.octavart.com/statics/aoshi/img/logo.jpg",
};

const char PROXY_HOST[][BUFSIZ] = {
    "devmpop.zoomdev.us",
    "devepmpop.zoomdev.us",
    "marketplaceop.zoom.us"
};

const char HTTP_METHOD[][HTTP_METHOD_SIZE] = {
    "POST",
    "PUT",
    "GET",
    "DELETE",
    "CONNECT",
    "PATCH",
    "TRACE",
    "OPTIONS",
    "HEAD"
};


ssize_t read_line(int fd, char * buf, ssize_t n) {
    ssize_t totRead = 0;
    size_t numRead;
    char ch;
    
    if (n <= 0 || buf == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    for (;;) {
        numRead = read(fd, &ch, 1);
        
        if (numRead == -1) {
            if (errno == EINTR) {
                continue;
            } else {
                return -1;
            }
        } else if (numRead == 0) {
            if (totRead == 0) {
                return 0;
            }
            
            break;
        } else {
            if (totRead < n - 1) {
                *buf++ = ch;
                totRead += 1;
            }
            
            if (ch == '\n') break;
        }
    }
    *buf = '\0';
    return totRead;
}

int read_ssl_line(SSL * ssl, char * buf, size_t n) {
    char ch;
    int r, sslErr, totRead = 0;
    
    for(;;) {
        r = SSL_read(ssl, &ch, 1);
        sslErr = SSL_get_error(ssl, r);
        
        if (sslErr == SSL_ERROR_ZERO_RETURN) {
            if (totRead == 0) {
                return 0;
            }
            break;
        } else if (sslErr == SSL_ERROR_NONE) {
            if (totRead < n - 1) {
                *buf++ = ch;
                totRead++;
                
                if (ch == '\n') break;
            } else {
                break;
            }
        } else {
            return -1;
        }
    }
    
    *buf = '\0';
    return totRead;
}

char * parser_req_line(char * reqLine, char * domain, char * port, char * method) {
    char path[65535];
    // mes split method
    char * mes = strchr(reqLine, ' ');
    // prs split line
    char * prs = strchr(mes + 1, ' ');
    
    
    if (mes == NULL || prs == NULL) {
        *method = '\0';
        return NULL;
    }
    *mes = '\0';
    *prs = '\0';
    
    // get method;
    strcpy(method, reqLine);
    
    if (strcmp(method, "CONNECT") == 0) {
        char * cols = strstr(mes + 1, ":");
        *cols = '\0';
        strcpy(domain, mes + 1);
        strcpy(port, cols + 1);
        return NULL;
    } else {
        char * newReq = (char *) calloc(1, 65635);
        // get http | https out
        char * ds = strstr(mes + 1, "//");
        if (ds == NULL) ds = mes + 1;
        else ds += 2;
        char * cols = strchr(ds, '/');
        strcpy(path, cols);
    
        if (cols == ds) {
            snprintf(newReq, 65635, "%s %s %s", method, ds, prs + 1);
        } else {
            *cols = '\0';
            char * dp = strchr(ds, ':');
            if (dp == NULL) {
                strcpy(port, "80");
                strcpy(domain, ds);
            } else {
                *dp = '\0';
                strcpy(domain, ds);
                strcpy(port, dp + 1);
            }
            
            snprintf(newReq, 65635, "%s %s %s", method, path, prs + 1);
        }
        return newReq;
    }
}

SSL_CTX * initialize_ctx() {
    const SSL_METHOD * method;
    SSL_CTX * ctx;
    
    SSL_library_init();
    SSL_load_error_strings();
    
    method = SSLv23_method();
    ctx = SSL_CTX_new(method);
    
    // if (SSL_CTX_use_certificate_file(ctx, "dev.mergebot.com.crt", SSL_FILETYPE_PEM) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     exit(EXIT_FAILURE);
    // }
    
    // if (SSL_CTX_use_PrivateKey_file(ctx, "dev.mergebot.com.key", SSL_FILETYPE_PEM) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     exit(EXIT_FAILURE);
    // }
    
    if (SSL_CTX_load_verify_locations(ctx, "/usr/local/etc/openssl@1.1/cert.pem", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    return ctx;
}

void check_cert(SSL * ssl, char * domain) {
    X509 * peer;
    char peername[256];
    
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        printf("certificate verify failed\n");
        exit(-1);
    }
    
    peer = SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peername, 256);
    printf("peername: %s\n", peername);
}


const char * isMatch(char * req_line, char * domain, const char * protocol, char * port) {
    
    char url[URISIZE];
    char req[URISIZE];
    strcpy(req, req_line);
    
    
    
    char * pe = strchr(req, ' ');
    if (pe == NULL) return NULL;
    
    char * pe2 = strchr(pe + 1, ' ');
    if (pe2 == NULL) return NULL;
    
    *pe2 = '\0';
    *pe = '\0';
    
    if (strcmp(port, "80") == 0 || strcmp(port, "443") == 0) {
        snprintf(url, URISIZE, "%s://%s%s", protocol, domain, pe + 1);
    } else {
        snprintf(url, URISIZE, "%s://%s:%s%s", protocol, domain, port, pe + 1);
    }
    
    
    for (int i = 0; i < MAPSIZE; i++) {
        const char * tempStr = PROXY_SOUR[i];
        if (strstr(url, tempStr) != NULL) {
            return PROXY_DEST[i];
        }
    }
    
    return NULL;
}


int tcp_connect(const char * domain, const char * port) {
    int connfd = -1;
    struct addrinfo  hint, *addr, *cur;
    int err;
    bzero(&hint, sizeof(hint));
    
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_V4MAPPED | AI_ALL;
    
    if ((err = getaddrinfo(domain, port, &hint, &addr)) != 0 ) {
        gai_strerror(err);
        return -1;
    }

    
    for (cur = addr; cur != NULL; cur = cur->ai_next) {
        if ((connfd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol)) < 0) continue;
        if (connect(connfd, cur->ai_addr, cur->ai_addrlen) == 0) break;
        close(connfd);
    }
    
    freeaddrinfo(addr);
    
    if (cur == NULL) return -1;
    return connfd;
}

int tcp_listen(const char * host, const char * port) {
    int listenfd = -1;
    struct addrinfo hint, * r, * cur;
    int err;
    int on = 1;
    bzero(&hint, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_flags = AI_PASSIVE;
    hint.ai_socktype = SOCK_STREAM;
    
    if ((err = getaddrinfo(host, port, &hint, &r)) != 0) {
        gai_strerror(err);
        return -1;
    }
    
    for (cur = r; cur != NULL; cur = cur->ai_next) {
        if ((listenfd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol)) == -1) continue;
        if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) continue;
        if (bind(listenfd, cur->ai_addr, cur->ai_addrlen) == 0) break;
        close(listenfd);
    }
    
    freeaddrinfo(r);
    if (cur == NULL) return -1;
    if (listen(listenfd, 10) == -1) return -1;
    return listenfd;
}


int http_request(const char * mapurl) {
    char url[BUFSIZ];
    int connfd = 0;
    char port[10];
    char path[BUFSIZ];
    char reqLine[BUFSIZ];
    char *protocalMark, *portMark, *domainMark, *pathMark, *domain, *protocal;
    
    strcpy(url, mapurl);
    protocalMark = strstr(url, "://");
    domainMark = strchr(protocalMark + 3, ':');
    
    if (domainMark != NULL) {
        *domainMark = '\0';
        domain = protocalMark + 3;
        portMark = strchr(domainMark + 1, '/');
        *portMark = '\0';
        strcpy(port, domainMark + 1);
        pathMark = portMark + 1;
    } else {
        strcpy(port, "80");
        domainMark = strchr(protocalMark + 3, '/');
        if (domainMark != NULL) *domainMark = '\0';
        domain = protocalMark + 3;
        pathMark = domainMark + 1;
    }
    
    *protocalMark = '\0';
    protocal = url;
    
    strcpy(path, "/");
    strcat(path, pathMark);
    
    printf("protocal: %s, domain: %s, port: %s, path: %s\n", protocal, domain, port, path);
    connfd = tcp_connect(domain, port);
    
    strcpy(reqLine, "GET ");
    strcat(reqLine, path);
    strcat(reqLine, " HTTP/1.1\r\n");
    
    // if (strcmp(protocal, "https") == 0) {
    
    // } else {
    //     write(connfd, reqLine, strlen(reqLine));
    //     write(connfd, hostHeader, strlen(reqLine));
    // }
    
    return connfd;
    
}

int isProxyHost(char * host) {
    for (int i = 0; i < HOSTSIZE; i++) {
        if (strcmp(host, PROXY_HOST[i]) == 0) {
            return 1;
        }
    }
    
    return 0;
}

int add_ext(X509 * cert, int nid, char * value) {
    X509_EXTENSION * ex;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, NULL, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex) {
        return -1;
    }
    
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}

void createCertificate(char * domain, SSL * ssl) {
    RSA * rsa, * certrsa;
    EVP_PKEY * pkey, *certpkey;
    FILE * fp;
    X509 * cert;
    FILE *rootFp;
    X509 * rootCert;
    
    
    certrsa = RSA_generate_key(
                               2048,   /* number of bits for the key - 2048 is a sensible value */
                               RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
                               NULL,   /* callback - can be NULL if we aren't displaying progress */
                               NULL    /* callback argument - not needed in this case */
                               );
    
    rsa = RSA_new();
    pkey = EVP_PKEY_new();
    certpkey = EVP_PKEY_new();
    rootCert = X509_new();
    
    EVP_PKEY_assign_RSA(certpkey, certrsa);
    
    if ((rootFp = fopen("./myCA.pem", "r")) == NULL) {
        oops("open rootCA.crt failed: ");
    }
    
    printf("file read success\n");
    
    if (PEM_read_X509(rootFp, &rootCert, NULL, NULL) == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    X509_NAME * root_subject_name = X509_get_subject_name(rootCert);
    
    printf("crt read success\n");
    
    // open privatekey file
    fp = fopen("./myCA.key", "r");
    if (fp == NULL) {
        oops("fopen failed: ");
    }
    
    // read private key
    if (PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL) == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    EVP_PKEY_assign_RSA(pkey, rsa);
    
    // create certificate
    cert = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    
    // set valid date ranger of this cert
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    
    // set public key
    X509_set_pubkey(cert, certpkey);
    
    // set info
    X509_NAME * name;
    name = X509_get_subject_name(cert);
    
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *) "JP", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *) "XWT Inc.", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) domain, -1, -1, 0);
    // X509_set_subject_name(cert, name);
    
    X509_set_issuer_name(cert, root_subject_name);
    char ev[BUFSIZ];
    sprintf(ev, "critical,DNS.1:%s", domain);
    printf("ev: %s\n", ev);
    int r = 0;
//    r = add_ext(cert, NID_subject_key_identifier, "hash");
    // int r = add_ext(cert, NID_subject_alt_name, "email:steve@openssl.org");
    if (r == -1) {
        printf("set failure\n");
    }
    
    // sign the certigicate
    X509_sign(cert, pkey, EVP_sha1());
    
    if (SSL_use_certificate(ssl, cert) == -1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (SSL_use_PrivateKey(ssl, certpkey) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    printf("cert create success\n");
}


RSA * resignCertificate(X509 * cert, SSL * ssl) {
    RSA * rsa, * certrsa;
    EVP_PKEY * pkey, *certpkey;
    FILE * fp;
    FILE *rootFp;
    X509 * rootCert;
    BIGNUM *e;
    
    e = BN_new();
    
    
    certrsa = RSA_new();
    rsa = RSA_new();
    pkey = EVP_PKEY_new();
    certpkey = EVP_PKEY_new();
    rootCert = X509_new();
    
    BN_set_word(e, RSA_F4);
    
    if (RSA_generate_key_ex(certrsa, 2048, e, NULL) == 0) {
        ERR_print_errors_fp(stdout);
        exit(EXIT_FAILURE);
    }
    
    
    
    EVP_PKEY_assign_RSA(certpkey, certrsa);
    
    if ((rootFp = fopen("/Users/wentaoxing/Documents/httpproxy/myCA.pem", "r")) == NULL) {
        oops("open rootCA.crt failed: ");
    }
    
    if (PEM_read_X509(rootFp, &rootCert, NULL, NULL) == NULL) {
        ERR_print_errors_fp(stdout);
        exit(EXIT_FAILURE);
    }
    
    X509_NAME * root_subject_name = X509_get_subject_name(rootCert);
    
    // open privatekey file
    fp = fopen("/Users/wentaoxing/Documents/httpproxy/myCA.key", "r");
    if (fp == NULL) {
        oops("fopen failed: ");
    }
    
    // read private key
    if (PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL) == NULL) {
        ERR_print_errors_fp(stdout);
        exit(EXIT_FAILURE);
    }
    
    // resign the certificate
    EVP_PKEY_assign_RSA(pkey, rsa);
    X509_set_issuer_name(cert, root_subject_name);
    X509_set_pubkey(cert, certpkey);
    X509_sign(cert, pkey, EVP_sha256());
    
    if (SSL_use_certificate(ssl, cert) == -1) {
        ERR_print_errors_fp(stdout);
        exit(EXIT_FAILURE);
    }
    
    if (SSL_use_PrivateKey(ssl, certpkey) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(EXIT_FAILURE);
    }
    
    
    fclose(rootFp);
    fclose(fp);
    
    RSA_free(rsa);
    X509_free(cert);
    BN_free(e);
    
    return certrsa;
}

// pthread

void Pthread_mutex_lock(pthread_mutex_t * mutex) {
    int n;
    if ((n = pthread_mutex_lock(mutex)) == 0) {
        return;
    }
    errno = n;
    oops("pthread mutex lock error: ");
}


void Pthread_mutex_unlock(pthread_mutex_t * mutex) {
    int n;
    if ((n = pthread_mutex_unlock(mutex)) == 0) {
        return;
    }
    errno = n;
    oops("pthread mutex unlock error: ");
}

void Pthread_cond_signal(pthread_cond_t * cond) {
    int n;
    if ((n = pthread_cond_signal(cond)) == 0) {
        return;
    }
    errno = n;
    oops("pthread cond signal error: ");
}

void Pthread_cond_wait(pthread_cond_t * cond, pthread_mutex_t * mutex) {
    int n;
    if ((n = pthread_cond_wait(cond, mutex)) == 0) {
        return;
    }
    errno = n;
    oops("pthread cond wait error: ");
}

void Pthread_create(pthread_t * t, const pthread_attr_t * attr,  void *(*start_routine)(void *), void * arg) {
    int n;
    if ((n = pthread_create(t, attr, start_routine, arg)) == 0) return;
    errno = n;
    oops("pthread create error: ");
}

void Pthread_detach(pthread_t t) {
    int n;
    if ((n = pthread_detach(t)) == 0) return;
    errno = n;
    oops("pthread detach error: ");
}

ssize_t parser_req_path(char * buf, ssize_t nbytes) {
    char * space, * slash;
    char reqLine[URISIZE];
    
    space = strchr(buf, ' ');
    slash = strstr(buf, "://");
    if (slash == NULL) return nbytes;
    slash = strchr(slash + 3, '/');
    *(space + 1) = '\0';
    strcpy(reqLine, buf);
    strcat(reqLine, slash);
    strcpy(buf, reqLine);
    return nbytes - (slash - (space + 1));
}

int is_req_line(char * buf) {
    char method[10], *space;
    long len;
    int i;
    
    space = strchr(buf, ' ');
    if (space == NULL) return 0;
    len = space - buf;
    if (len > HTTP_METHOD_MAX_LENGTH) return 0;
    
    strncpy(method, buf, len);
    method[len] = '\0';
    
    for (i = 0; i < HTTP_METHOD_SIZE; i++) {
        if (strcmp(method, HTTP_METHOD[i]) == 0) {
            return 1;
        }
    }
    
    return 0;
}
