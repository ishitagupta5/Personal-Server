/*
 * Skeleton files for personal server assignment.
 *
 * @author Godmar Back
 * written for CS3214, Spring 2018.
 */

#include <pthread.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "buffer.h"
#include "hexdump.h"
#include "http.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"

// Added to handle concurrent clients using threads.
static void *handle_client_thread(void *arg);

/* Implement HTML5 fallback.
 * If HTML5 fallback is implemented and activated, the server should
 * treat requests to non-API paths specially.
 * If the requested file is not found, the server will serve /index.html
 * instead; that is, it should treat the request as if it
 * had been for /index.html instead.
 */
bool html5_fallback = false;

// silent_mode. During benchmarking, this will be true
bool silent_mode = false;

// default token expiration time is 1 day
int token_expiration_time = 24 * 60 * 60;

// root from which static files are served

char *server_root;

/* 
 * Thread function to handle a single client's HTTP transactions.
 * Repeatedly processes transactions until the client disconnects 
 * or the connection is no longer keep-alive.
 */
static void *handle_client_thread(void *arg) {
    struct http_client *client = arg;
    for (;;) {
        // Handle a single HTTP transaction.
        bool success = http_handle_transaction(client);
        if (!success || !client->keep_alive) {
            // Exit loop if the transaction fails or connection is not persistent.
            break;
        }
    }
    // Clean up resources after handling the client.
    bufio_close(client->bufio);
    free(client);
    return NULL;
}

/*
 * A non-concurrent, iterative server that serves one client at a time.
 * For each client, it handles exactly 1 HTTP transaction.
 */
static void
server_loop(char *port_string)
{
    int accepting_socket = socket_open_bind_listen(port_string, 10000);
    while (accepting_socket != -1) {
        fprintf(stderr, "Waiting for client...\n");
       // Accept a new client connection.
        int client_socket = socket_accept_client(accepting_socket);
        if (client_socket == -1)
            return;

        // Allocate memory for a new client structure.
        struct http_client *client = malloc(sizeof(*client));

        http_setup_client(client, bufio_create(client_socket));

        // Create a thread to handle the client.
        pthread_t tid;
        int rc = pthread_create(&tid, NULL, handle_client_thread, client);
        if (rc != 0) {
            // Handle thread creation failure.        
            fprintf(stderr, "Error creating thread: %s\n", strerror(rc));
            bufio_close(client->bufio);
            free(client);
            continue;
        }
        // Detach the thread to avoid resource leaks.
        pthread_detach(tid);
    }
}

static void
usage(char * av0)
{
    fprintf(stderr, "Usage: %s -p port [-R rootdir] [-h] [-e seconds]\n"
        "  -p port      port number to bind to\n"
        "  -R rootdir   root directory from which to serve files\n"
        "  -e seconds   expiration time for tokens in seconds\n"
        "  -a           enable HTML5 fallback\n"
        "  -h           display this help\n"
        , av0);
    exit(EXIT_FAILURE);
}

int
main(int ac, char *av[])
{
    int opt;
    char *port_string = NULL;
    // Parse command-line arguments.
    while ((opt = getopt(ac, av, "ahp:R:se:")) != -1) {
        switch (opt) {
            case 'a':
                html5_fallback = true;
                break;

            case 'p':
                port_string = optarg;
                break;

            case 'e':
                token_expiration_time = atoi(optarg);
                fprintf(stderr, "token expiration time is %d\n", token_expiration_time);
                break;

            case 's':
                silent_mode = true;
                break;

            case 'R':
                server_root = optarg;
                break;

            case 'h':
            default:    /* '?' */
                usage(av[0]);
        }
    }

    if (port_string == NULL)
        usage(av[0]);

    /* We ignore SIGPIPE to prevent the process from terminating when it tries
     * to send data to a connection that the client already closed.
     * This may happen, in particular, in bufio_sendfile.
     */ 
    signal(SIGPIPE, SIG_IGN);

    fprintf(stderr, "Using port %s\n", port_string);
    server_loop(port_string);
    exit(EXIT_SUCCESS);
}

