/*
 * Support functions for dealing with sockets.
 *
 * Note: these functions cannot be used out of the box. 
 * In particular, support for protocol independent programming
 * is not fully implemented.  See below.
 *
 * Written by G. Back for CS 3214 Spring 2018.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "socket.h"
#include "main.h"

/*
 * Find a suitable IPv4 address to bind to, create a socket, bind it,
 * invoke listen to get the socket ready for accepting clients.
 *
 * This function does not implement proper support for protocol-independent/
 * dual-stack binding.  Adding this is part of the assignment. 
 *
 * Returns -1 on error, setting errno.
 * Returns socket file descriptor otherwise.
 */
int 
socket_open_bind_listen(char * port_number_string, int backlog)
{
    struct addrinfo *info, *pinfo;
    struct addrinfo hint;

    memset(&hint, 0, sizeof hint);

    hint.ai_flags = AI_PASSIVE |    // we're looking for an address to bind to
                    AI_NUMERICSERV; // service port is numeric, don't look in /etc/services

    hint.ai_protocol = IPPROTO_TCP; // only interested in TCP
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_family = AF_UNSPEC; // Allow both IPv4 and IPv6, enabling dual-stack
    int rc = getaddrinfo(NULL, port_number_string, &hint, &info);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(rc));
        return -1;
    }

    int listening_socket = -1;
    char printed_addr[1024];
    for (pinfo = info; pinfo; pinfo = pinfo->ai_next) {
        if (pinfo->ai_family != AF_INET6)
            continue;
        int rc = getnameinfo(pinfo->ai_addr, pinfo->ai_addrlen,
                             printed_addr, sizeof printed_addr, NULL, 0,
                             NI_NUMERICHOST);
        if (rc != 0) {
            fprintf(stderr, "getnameinfo error: %s\n", gai_strerror(rc));
            continue;
        }

        /* Uncomment this to see the address returned
        printf("%s: %s\n", pinfo->ai_family == AF_INET ? "AF_INET" :
                           pinfo->ai_family == AF_INET6 ? "AF_INET6" : "?", 
                           printed_addr);
        */

        /* Skip any non-IPv4 addresses.  
         * Adding support for protocol independence/IPv6 is part of the project.
         */
        // if (pinfo->ai_family != AF_INET)
        //     continue;

        int s = socket(pinfo->ai_family, pinfo->ai_socktype, pinfo->ai_protocol);
        if (s == -1) {
            perror("socket");
            continue;
        }

        // See https://stackoverflow.com/a/3233022 for a good explanation of what this does
        int opt = 1;
        setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt));

        if (bind(s, pinfo->ai_addr, pinfo->ai_addrlen) == -1) {
            close(s);
            continue;
        }
        if (listen(s, backlog) == -1) {
            perror("listen");
            close(s);
            continue;
        }

        listening_socket = s;
        break; 
    }

    if (listening_socket == -1) {
        for (pinfo = info; pinfo; pinfo = pinfo->ai_next) {
            if (pinfo->ai_family != AF_INET)
                continue;

            int rc = getnameinfo(pinfo->ai_addr, pinfo->ai_addrlen,
                                 printed_addr, sizeof printed_addr, NULL, 0,
                                 NI_NUMERICHOST);
            if (rc != 0) {
                fprintf(stderr, "getnameinfo error: %s\n", gai_strerror(rc));
                continue;
            }

            int s = socket(pinfo->ai_family, pinfo->ai_socktype, pinfo->ai_protocol);
            if (s == -1)
                continue;

            int opt = 1;
            setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt));

            if (bind(s, pinfo->ai_addr, pinfo->ai_addrlen) == -1) {
                close(s);
                continue;
            }

            if (listen(s, backlog) == -1) {
                perror("listen");
                close(s);
                continue;
            }

            listening_socket = s;
            break;
        }
    }

    freeaddrinfo(info);

    if (listening_socket == -1) {
        fprintf(stderr, "No suitable address to bind port %s found\n", port_number_string);
        return -1;
    }

    return listening_socket;

}

/**
 * Accept a client, blocking if necessary.
 *
 * Returns file descriptor of client accepted on success, returns
 * -1 on error.
 */
int 
socket_accept_client(int accepting_socket)
{
    /* The address passed into accept must be large enough for either IPv4 & IPv6.
     * Using a struct sockaddr is too small to hold a full IPv6 address and accept()
     * would not return the full address.
     */
    struct sockaddr_storage peer;
    socklen_t peersize = sizeof(peer);

    int client = accept(accepting_socket, (struct sockaddr *) &peer, &peersize);
    if (client == -1) {
        perror("accept");
        return -1;
    }

    /* Performance tuning.  Turn off Nagle's algorithm.
     * Otherwise, when the servers sends a reply to the client, and the reply
     * is small relative to the MSS size, there would be a delay of 40ms
     * during which the OS would hope in vain for more data to be sent.
     * See tcp(7)
     */
    int i = 1;
    setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i));

    /* The following will help with debugging your server.
     * Adjust and/or remove as you see fit.
     */
    if (!silent_mode) {
        char peer_addr[1024], peer_port[10];
        int rc = getnameinfo((struct sockaddr *) &peer, peersize,
                             peer_addr, sizeof peer_addr, peer_port, sizeof peer_port,
                             NI_NUMERICHOST | NI_NUMERICSERV);
        if (rc != 0) {
            fprintf(stderr, "getnameinfo error: %s\n", gai_strerror(rc));
            return -1;
        }
        fprintf(stderr, "Accepted connection from %s:%s\n", peer_addr, peer_port);
    }
    return client;
}

