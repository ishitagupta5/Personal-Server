/*
 * A partial implementation of HTTP/1.0
 *
 * This code is mainly intended as a replacement for the book's 'tiny.c' server
 * It provides a *partial* implementation of HTTP/1.0 which can form a basis for
 * the assignment.
 *
 * @author G. Back for CS 3214 Spring 2018
 */
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <assert.h>
#include <linux/limits.h>
#include <jansson.h>
#include <jwt.h>
#include <time.h>
#include <dirent.h>
#include <sys/types.h>


#include "http.h"
#include "hexdump.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"

// Need macros here because of the sizeof
#define CRLF "\r\n"
#define CR "\r"
#define STARTS_WITH(field_name, header) \
    (!strncasecmp(field_name, header, sizeof(header) - 1))

// Added a global constant for the secret key used to sign and validate JWT tokens.
const char *jwt_secret_key = "big balls";

/* Parse HTTP request line, setting req_method, req_path, and req_version. */
static bool
http_parse_request(struct http_transaction *ta)
{
    size_t req_offset;
    ssize_t len = bufio_readline(ta->client->bufio, &req_offset);
    if (len < 2)       // error, EOF, or less than 2 characters
        return false;

    char *request = bufio_offset2ptr(ta->client->bufio, req_offset);
    request[len-2] = '\0';  // replace LF with 0 to ensure zero-termination
    char *endptr;
    char *method = strtok_r(request, " ", &endptr);
    if (method == NULL)
        return false;

    if (!strcmp(method, "GET"))
        ta->req_method = HTTP_GET;
    else if (!strcmp(method, "POST"))
        ta->req_method = HTTP_POST;
    else
        ta->req_method = HTTP_UNKNOWN;

    char *req_path = strtok_r(NULL, " ", &endptr);
    if (req_path == NULL)
        return false;

    ta->req_path = bufio_ptr2offset(ta->client->bufio, req_path);

    char *http_version = strtok_r(NULL, CR, &endptr);
    if (http_version == NULL)  // would be HTTP 0.9
        return false;

    // Updated to record the client's HTTP version for compatibility with HTTP/1.1.
    if (!strcmp(http_version, "HTTP/1.1"))
        ta->req_version = HTTP_1_1;
    else if (!strcmp(http_version, "HTTP/1.0"))
        ta->req_version = HTTP_1_0;
    else
        return false;

    return true;
}

/* Process HTTP headers. */
static bool
http_process_headers(struct http_transaction *ta)
{
    // Ensured default initialization of fields for HTTP/1.1 support and authentication.
    ta->req_content_len = 0;
    ta->range_start = -1;
    ta->range_end = -1;
    // Support for persistent connections.
    ta->want_keep_alive = (ta->req_version == HTTP_1_1);
    ta->is_authenticated = false; 

    for (;;) {
        size_t header_offset;
        ssize_t len = bufio_readline(ta->client->bufio, &header_offset);
        if (len <= 0)
            return false;

        char *header = bufio_offset2ptr(ta->client->bufio, header_offset);
        if (len == 2 && STARTS_WITH(header, CRLF))       // empty CRLF
            return true;

        header[len-2] = '\0';
        /* Each header field consists of a name followed by a 
         * colon (":") and the field value. Field names are 
         * case-insensitive. The field value MAY be preceded by 
         * any amount of LWS, though a single SP is preferred.
         */
        char *endptr;
        char *field_name = strtok_r(header, ":", &endptr);
        if (field_name == NULL)
            return false;

        // skip white space
        char *field_value = endptr;
        while (*field_value == ' ' || *field_value == '\t')
            field_value++;

        // Added logic to handle Content-Length header and range requests for partial content.
        // you may print the header like so
        // printf("Header: %s: %s\n", field_name, field_value);
        if (!strcasecmp(field_name, "Content-Length")) {
            ta->req_content_len = atoi(field_value);
        }

        /* Handle other headers here. Both field_value and field_name
         * are zero-terminated strings.
         */
        if (!strcasecmp(field_name, "Connection")) {
            if (!strcasecmp(field_value, "close"))
                ta->want_keep_alive = false;
        }
        /* Handle the 'Range' header.
        * If the header value starts with 'bytes=', parse
        * the byte range and update the start and end positions accordingly.
        */
        // Added support for parsing the 'Range' header to handle partial content requests.
        if (!strcasecmp(field_name, "Range")) {
            if (!strncasecmp(field_value, "bytes=", 6)) {
                char *r = field_value + 6;
                char *dash = strchr(r, '-');
                if (dash) {
                    *dash = '\0';
                    if (*r)
                        ta->range_start = atoll(r);
                    char *endp = dash+1;
                    if (*endp)
                        ta->range_end = atoll(endp);
                }
            }
        }

        // Integrated JWT token validation to determine authentication state.
        if (!strcasecmp(field_name, "Cookie")) {
            ta->cookie = bufio_ptr2offset(ta->client->bufio, field_value);

            //extract and validate authentication token ('auth_jwt') from cookies.
            char *cookie_header = bufio_offset2ptr(ta->client->bufio, ta->cookie);
            char *copy = strdup(cookie_header);
            char *token = NULL;
            char *saveptr = NULL;
            char *part = strtok_r(copy, ";", &saveptr);
            while (part) {
                char *eq = strchr(part, '=');
                if (eq) {
                    *eq = '\0';
                    char *name = part;
                    char *value = eq + 1;
                    while (*name == ' ' || *name == '\t') name++;
                    while (*value == ' ' || *value == '\t') value++;
                    if (!strcasecmp(name, "auth_jwt")) {
                        token = strdup(value);
                        break;
                    }
                }
                part = strtok_r(NULL, ";", &saveptr);
            }
            free(copy);

            // Validate JWT token and set authentication status.
            if (token) {
                jwt_t *jwt = NULL;
                if (jwt_decode(&jwt, token, (unsigned char *)jwt_secret_key, (int)strlen(jwt_secret_key)) == 0) {
                    time_t exp = jwt_get_grant_int(jwt, "exp");
                    time_t now = time(NULL);
                    if (exp > now) { // Token is valid and not expired
                        ta->is_authenticated = true;
                    }
                    jwt_free(jwt);
                }
                free(token);
            }
        }
    }
}


const int MAX_HEADER_LEN = 2048;

/* add a formatted header to the response buffer. */
void 
http_add_header(buffer_t * resp, char* key, char* fmt, ...)
{
    va_list ap;

    buffer_appends(resp, key);
    buffer_appends(resp, ": ");

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(resp, MAX_HEADER_LEN);
    int len = vsnprintf(error, MAX_HEADER_LEN, fmt, ap);
    resp->len += len > MAX_HEADER_LEN ? MAX_HEADER_LEN - 1 : len;
    va_end(ap);

    buffer_appends(resp, "\r\n");
}

/* add a content-length header. */
static void
add_content_length(buffer_t *res, size_t len)
{
    http_add_header(res, "Content-Length", "%ld", len);
}

/* start the response by writing the first line of the response 
 * to the response buffer.  Used in send_response_header */
static void
start_response(struct http_transaction * ta, buffer_t *res)
{
    buffer_init(res, 80);

    /* Hint: you must change this as you implement HTTP/1.1.
     * Respond with the highest version the client supports
     * as indicated in the version field of the request.
     */
    if (ta->req_version == HTTP_1_1) {
        buffer_appends(res, "HTTP/1.1 ");
    } else {
        buffer_appends(res, "HTTP/1.0 ");
    }

    switch (ta->resp_status) {
    case HTTP_OK:
        buffer_appends(res, "200 OK");
        break;
    case HTTP_PARTIAL_CONTENT:
        buffer_appends(res, "206 Partial Content");
        break;
    case HTTP_BAD_REQUEST:
        buffer_appends(res, "400 Bad Request");
        break;
    case HTTP_PERMISSION_DENIED:
        buffer_appends(res, "403 Permission Denied");
        break;
    case HTTP_NOT_FOUND:
        buffer_appends(res, "404 Not Found");
        break;
    case HTTP_METHOD_NOT_ALLOWED:
        buffer_appends(res, "405 Method Not Allowed");
        break;
    case HTTP_REQUEST_TIMEOUT:
        buffer_appends(res, "408 Request Timeout");
        break;
    case HTTP_REQUEST_TOO_LONG:
        buffer_appends(res, "414 Request Too Long");
        break;
    case HTTP_NOT_IMPLEMENTED:
        buffer_appends(res, "501 Not Implemented");
        break;
    case HTTP_SERVICE_UNAVAILABLE:
        buffer_appends(res, "503 Service Unavailable");
        break;
    case HTTP_INTERNAL_ERROR:
        buffer_appends(res, "500 Internal Server Error");
        break;
    default:  /* else */
        buffer_appends(res, "500 This is not a valid status code."
                "Did you forget to set resp_status?");
        break;
    }
    buffer_appends(res, CRLF);
}

/* Send response headers to client in a single system call. */
static bool
send_response_header(struct http_transaction *ta)
{
    buffer_t response;
    start_response(ta, &response);
    buffer_appends(&ta->resp_headers, CRLF);

    buffer_t *response_and_headers[2] = {
        &response, &ta->resp_headers
    };

    int rc = bufio_sendbuffers(ta->client->bufio, response_and_headers, 2);
    buffer_delete(&response);
    return rc != -1;
}

/* Send a full response to client with the content in resp_body. */
static bool
send_response(struct http_transaction *ta)
{
    // add content-length.  All other headers must have already been set.
    add_content_length(&ta->resp_headers, ta->resp_body.len);
    buffer_appends(&ta->resp_headers, CRLF);

    buffer_t response;
    start_response(ta, &response);

    buffer_t *response_and_headers[3] = {
        &response, &ta->resp_headers, &ta->resp_body
    };

    int rc = bufio_sendbuffers(ta->client->bufio, response_and_headers, 3);
    buffer_delete(&response);
    return rc != -1;
}

const int MAX_ERROR_LEN = 2048;

/* Send an error response. */
static bool
send_error(struct http_transaction * ta, enum http_response_status status, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(&ta->resp_body, MAX_ERROR_LEN);
    int len = vsnprintf(error, MAX_ERROR_LEN, fmt, ap);
    ta->resp_body.len += len > MAX_ERROR_LEN ? MAX_ERROR_LEN - 1 : len;
    va_end(ap);
    ta->resp_status = status;
    http_add_header(&ta->resp_headers, "Content-Type", "text/plain");
    return send_response(ta);
}

/* Send Not Found response. */
static bool
send_not_found(struct http_transaction *ta)
{
    return send_error(ta, HTTP_NOT_FOUND, "File %s not found", 
        bufio_offset2ptr(ta->client->bufio, ta->req_path));
}

/* A start at assigning an appropriate mime type.  Real-world 
 * servers use more extensive lists such as /etc/mime.types
 */
static const char *
guess_mime_type(char *filename)
{
    char *suffix = strrchr(filename, '.');
    if (suffix == NULL)
        return "text/plain";

    if (!strcasecmp(suffix, ".html"))
        return "text/html";

    if (!strcasecmp(suffix, ".gif"))
        return "image/gif";

    if (!strcasecmp(suffix, ".png"))
        return "image/png";

    if (!strcasecmp(suffix, ".jpg"))
        return "image/jpeg";

    if (!strcasecmp(suffix, ".js"))
        return "text/javascript";

    /* hint: you need to add support for (at least) .css, .svg, and .mp4
     * You can grep /etc/mime.types for the correct types */
    
    // Extended MIME type support for '.css', '.svg', and '.mp4' files.
    if (!strcasecmp(suffix, ".css"))
        return "text/css";
    if (!strcasecmp(suffix, ".svg"))
        return "image/svg+xml";
    if (!strcasecmp(suffix, ".mp4"))
        return "video/mp4";
    return "text/plain";
}

/* Handle HTTP transaction for static files. */
//for videos parse the arnge header in process headers, then make sure wont go off end of file , take range and send 
static bool
handle_static_asset(struct http_transaction *ta, char *basedir)
{
    char fname[PATH_MAX];

    // assert (basedir != NULL || !!!"No base directory. Did you specify -R?");
    // Added protection against path traversal attacks by rejecting requests containing "..".
    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    // The code below is vulnerable to an attack.  Can you see
    // which?  Fix it to avoid indirect object reference (IDOR) attacks.
    // Prevent path traversal attacks by rejecting requests containing "..".
    if (strstr(req_path, "..")) {
        return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied");
    }

    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);
    // Implemented HTML5 fallback logic to serve index.html or 200.html if the requested file does not exist.
    //handling html5fallback
    //reutnring the required paths and error whene no path avaialble
    //used stat to check if file exists
    if (html5_fallback) {
        struct stat st;

        if ((strcmp(req_path, "/") == 0) || (strcmp(req_path, "") == 0)) {
            snprintf(fname, sizeof fname, "%s/index.html", basedir);
        } else if (stat(fname, &st) != 0 || !S_ISREG(st.st_mode)) {
            snprintf(fname, sizeof fname, "%s%s.html", basedir, req_path);
            if (stat(fname, &st) != 0 || !S_ISREG(st.st_mode)) {
                snprintf(fname, sizeof fname, "%s", basedir);
                if (stat(fname, &st) != 0 || !S_ISREG(st.st_mode)) {
                    snprintf(fname, sizeof fname, "%s/200.html", basedir);
                }
            }
        }
    }

    if (access(fname, R_OK) == -1) {
        if (errno == EACCES)
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        else
            return send_not_found(ta);
    }

    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    /* Remove this line once your code handles this case */
    // assert (!(html5_fallback && rc == 0 && S_ISDIR(st.st_mode)));

    if (rc == -1)
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");

    int filefd = open(fname, O_RDONLY);
    if (filefd == -1) {
        return send_not_found(ta);
    }

    // Added 'Accept-Ranges' header for partial content support.
    http_add_header(&ta->resp_headers, "Accept-Ranges", "bytes");
    off_t filesize = st.st_size;
    off_t from = 0, to = filesize - 1;

    //Check if this is a range request
    if (ta->range_start != -1) {
        //adjust start
        if (ta->range_start < 0) ta->range_start = 0; 
        if (ta->range_start >= filesize) {
            //Invalid range
            close(filefd);
            ta->resp_status = HTTP_BAD_REQUEST;
            return send_response(ta);
        }
        from = ta->range_start;

        //adjust end
        if (ta->range_end == -1 || ta->range_end >= filesize) {
            to = filesize - 1;
        } else {
            to = ta->range_end;
        }

        //now partial content
        ta->resp_status = HTTP_PARTIAL_CONTENT;
        off_t content_length = to - from + 1;
        http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));
        http_add_header(&ta->resp_headers, "Content-Range", "bytes %ld-%ld/%ld", (long)from, (long)to, (long)filesize);
        http_add_header(&ta->resp_headers, "Content-Length", "%ld", (long)content_length);
        
        if (!send_response_header(ta)) {
            close(filefd);
            return false;
        }

        bool success = true;
        while (success && from <= to)
            success = bufio_sendfile(ta->client->bufio, filefd, &from, to + 1 - from) > 0;

        close(filefd);
        return success;
    } else {
        //normal request (no Range)
        ta->resp_status = HTTP_OK;
        http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));
        add_content_length(&ta->resp_headers, filesize);

        if (!send_response_header(ta)) {
            close(filefd);
            return false;
        }

        bool success = true;
        off_t sent = 0;
        while (success && sent < filesize)
            success = bufio_sendfile(ta->client->bufio, filefd, &sent, filesize - sent) > 0;

        close(filefd);
        return success;
    }
}
/*
Your server should implement the entry point /api/login which then goes to private in auth
When used in a GET request, /api/login should return the claims the client presented in its request as a JSON object if the user is authenticated, or an empty object
{} if not.
Your server should implement the entry point /api/logout as well
api login post get
api logout post 
video later on i think - go through and find video files in server root, find all that end in mp4, print json

 */
static bool handle_api(struct http_transaction *ta) {
    extern int token_expiration_time; // Assume defined globally
    char *req_path_ptr = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    extern char *server_root;

    const char *env_user = getenv("USER_NAME");
    if (!env_user) env_user = "user";
    const char *env_pass = getenv("USER_PASS");
    if (!env_pass) env_pass = "pass";
    const char *jwt_secret_key = getenv("SECRET");
    if (!jwt_secret_key) jwt_secret_key = "your_secret_key";

    // Initialize authentication field
    ta->is_authenticated = false;
    // Added '/api/login' endpoint for handling user authentication.
    if (strcmp(req_path_ptr, "/api/login") == 0) {
    if (ta->req_method == HTTP_GET) {
        // Respond with JWT claims if authenticated, or an empty object if not.
        char *cookie_header = NULL;
        if (ta->cookie != 0) {
            cookie_header = bufio_offset2ptr(ta->client->bufio, ta->cookie);
        }

        char *token = NULL;
        if (cookie_header) {
            char *copy = strdup(cookie_header);
            char *saveptr = NULL;
            char *part = strtok_r(copy, ";", &saveptr);
            while (part) {
                char *eq = strchr(part, '=');
                if (eq) {
                    *eq = '\0';
                    char *name = part;
                    char *value = eq + 1;
                    if (!strcasecmp(name, "auth_jwt")) {
                        token = strdup(value);
                        break;
                    }
                }
                part = strtok_r(NULL, ";", &saveptr);
            }
            free(copy);
        }

        json_t *claims = NULL;
        if (token) {
            jwt_t *jwt = NULL;
            if (jwt_decode(&jwt, token, (unsigned char *)jwt_secret_key, (int)strlen(jwt_secret_key)) == 0) {
                time_t exp = (time_t)jwt_get_grant_int(jwt, "exp");
                time_t now = time(NULL);
                if (exp >= now) {
                    ta->is_authenticated = true;

                    // Extract JWT claims
                    const char *sub = jwt_get_grant(jwt, "sub");
                    claims = json_object();
                    json_object_set_new(claims, "sub", json_string(sub ? sub : ""));
                    json_object_set_new(claims, "iat", json_integer(jwt_get_grant_int(jwt, "iat")));
                    json_object_set_new(claims, "exp", json_integer(exp));
                }
                jwt_free(jwt);
            }
            free(token);
        }

        ta->resp_status = 200; // OK
        http_add_header(&ta->resp_headers, "Content-Type", "application/json");
        if (claims) {
            char *resp_str = json_dumps(claims, 0);
            json_decref(claims);
            buffer_appends(&ta->resp_body, resp_str);
            free(resp_str);
        } else {
            buffer_appends(&ta->resp_body, "{}");
        }
        return send_response(ta);
    }
 else if (ta->req_method == HTTP_POST) {
            // Validate credentials, issue JWT token, and set it in the 'auth_jwt' cookie.
            char *body = bufio_offset2ptr(ta->client->bufio, ta->req_body);
            json_error_t error;
            json_t *root = json_loadb(body, ta->req_content_len, 0, &error);
            if (!root || !json_is_object(root)) {
                if (root) json_decref(root);
                ta->resp_status = 400;
                http_add_header(&ta->resp_headers, "Content-Type", "application/json");
                return send_response(ta);
            }

            const char *username = NULL, *password = NULL;
            json_t *uobj = json_object_get(root, "username");
            json_t *pobj = json_object_get(root, "password");
            if (json_is_string(uobj)) username = json_string_value(uobj);
            if (json_is_string(pobj)) password = json_string_value(pobj);

            if (username && password && strcmp(username, env_user) == 0 && strcmp(password, env_pass) == 0) {
            jwt_t *jwt;
            jwt_new(&jwt);

            // Add claims to the JWT
            jwt_add_grant(jwt, "sub", username); // Subject claim (username)
            time_t now = time(NULL);             // Current time
            jwt_add_grant_int(jwt, "iat", now);  // Issued-at claim
            jwt_add_grant_int(jwt, "exp", now + token_expiration_time); // Expiration claim

            // Set the JWT algorithm and secret
            jwt_set_alg(jwt, JWT_ALG_HS256, (const unsigned char *)jwt_secret_key, (int)strlen(jwt_secret_key));
            char *token = jwt_encode_str(jwt);

            // Respond with token and set cookie
            ta->resp_status = 200;
            http_add_header(&ta->resp_headers, "Content-Type", "application/json");
            http_add_header(&ta->resp_headers, "Set-Cookie", "auth_jwt=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d", token, token_expiration_time);

            // Include claims in the response body
            json_t *claims = json_object();
            json_object_set_new(claims, "sub", json_string(username));
            json_object_set_new(claims, "iat", json_integer(now));
            json_object_set_new(claims, "exp", json_integer(now + token_expiration_time));

            char *resp_str = json_dumps(claims, 0);
            buffer_appends(&ta->resp_body, resp_str);
            free(resp_str);
            json_decref(claims);

            jwt_free(jwt);
            free(token);
            json_decref(root);
            return send_response(ta);
        }
        else {
                json_decref(root);
                ta->resp_status = 403;
                http_add_header(&ta->resp_headers, "Content-Type", "application/json");
                return send_response(ta);
            }
        } else {
            return send_error(ta, 405, "Method not allowed");
        }
    }

    // Added '/api/logout' endpoint to clear the JWT token from the cookie.
    if (strcmp(req_path_ptr, "/api/logout") == 0) {
        if (ta->req_method == HTTP_POST) {
            // Clear 'auth_jwt' cookie and respond with a logged-out status.
            http_add_header(&ta->resp_headers, "Set-Cookie", "auth_jwt=; Max-Age=0; Path=/; HttpOnly");
            ta->resp_status = 200;
            http_add_header(&ta->resp_headers, "Content-Type", "application/json");
            buffer_appends(&ta->resp_body, "{\"status\": \"logged_out\"}");
            return send_response(ta);
        } else {
            return send_error(ta, 405, "Method not allowed");
        }
    }

    // Added '/api/video' endpoint to list all '.mp4' files in the server root directory as JSON.
    if (strcmp(req_path_ptr, "/api/video") == 0) {
        if (ta->req_method == HTTP_GET) {
            // Open server root directory, find all '.mp4' files, and respond with their details in JSON format.
            DIR *dir = opendir(server_root);
            if (!dir) {
                ta->resp_status = HTTP_INTERNAL_ERROR;
                http_add_header(&ta->resp_headers, "Content-Type", "text/plain");
                buffer_appends(&ta->resp_body, "Could not open directory");
                return send_response(ta);
            }

            json_t *video_array = json_array();
            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL) {
                char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", server_root, entry->d_name);

            struct stat st;
            if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
                char *name = entry->d_name;
                char *ext = strrchr(name, '.');
                if (ext && !strcasecmp(ext, ".mp4")) {
                    json_t *obj = json_object();
                    json_object_set_new(obj, "name", json_string(name));
                    json_object_set_new(obj, "size", json_integer((json_int_t)st.st_size));
                    json_array_append_new(video_array, obj);
                }
            }
            }
            closedir(dir);

            char *resp_str = json_dumps(video_array, 0);
            json_decref(video_array);

            ta->resp_status = HTTP_OK;
            http_add_header(&ta->resp_headers, "Content-Type", "application/json");
            buffer_appends(&ta->resp_body, resp_str);
            free(resp_str);

            return send_response(ta);
        } else {
            return send_error(ta, HTTP_METHOD_NOT_ALLOWED, "Method not allowed");
        }
    }

    return send_error(ta, 404, "Not Found");
}


/* Set up an http client, associating it with a bufio buffer. */
void 
http_setup_client(struct http_client *self, struct bufio *bufio)
{
    self->bufio = bufio;
}

/* Handle a single HTTP transaction.  Returns true on success. */
bool
http_handle_transaction(struct http_client *self)
{
    // if it's http 1.1 it should be true
    struct http_transaction ta;
    memset(&ta, 0, sizeof ta);
    ta.client = self;

    if (!http_parse_request(&ta))
        return false;

    if (!http_process_headers(&ta))
        return false;

    if (ta.req_content_len > 0) {
        int rc = bufio_read(self->bufio, ta.req_content_len, &ta.req_body);
        if (rc != ta.req_content_len)
            return false;

        // To see the body, use this:
        // char *body = bufio_offset2ptr(ta.client->bufio, ta.req_body);
        // hexdump(body, ta.req_content_len);
    }

    buffer_init(&ta.resp_headers, 1024);
    http_add_header(&ta.resp_headers, "Server", "CS3214-Personal-Server");
    buffer_init(&ta.resp_body, 0);

    bool rc = false;
    char *req_path = bufio_offset2ptr(ta.client->bufio, ta.req_path);
    if (STARTS_WITH(req_path, "/api")) {
        rc = handle_api(&ta);
    }
    // Authenticate '/private' requests by validating the JWT token in the 'auth_jwt' cookie.
    else if (STARTS_WITH(req_path, "/private")) {
    char *cookie_header = NULL;
    if (ta.cookie != 0) {
        cookie_header = bufio_offset2ptr(self->bufio, ta.cookie);
    }

    ta.is_authenticated = false;
    if (cookie_header) {
        char *copy = strdup(cookie_header);
        char *saveptr = NULL;
        char *part = strtok_r(copy, ";", &saveptr);
        while (part) {
            while (*part == ' ' || *part == '\t') part++;
            char *eq = strchr(part, '=');
            if (eq) {
                *eq = '\0';
                char *name = part;
                char *value = eq + 1;
                while (*value == ' ' || *value == '\t') value++;

                if (!strcasecmp(name, "auth_jwt")) {
                    const char *jwt_secret = getenv("SECRET");
                    if (!jwt_secret) jwt_secret = "your_secret_key";

                    jwt_t *jwt = NULL;
                    if (jwt_decode(&jwt, value, (unsigned char *)jwt_secret, (int)strlen(jwt_secret)) == 0) {
                        time_t exp = jwt_get_grant_int(jwt, "exp");
                        time_t now = time(NULL);
                        if (exp > now) {
                            ta.is_authenticated = true;
                        }
                        jwt_free(jwt);
                    }
                }
            }
            part = strtok_r(NULL, ";", &saveptr);
        }
        free(copy);
    }

    // Allow access if authenticated; deny otherwise
    if (!ta.is_authenticated) {
        ta.resp_status = 403; // HTTP_FORBIDDEN
        send_response(&ta);
        return true;
    }

    // If authenticated, proceed to serve the requested file
    if (strstr(req_path, "..")) {
        ta.resp_status = 404; // Prevent path traversal
        send_response(&ta);
        return true;
    }

    return handle_static_asset(&ta, server_root);
}

     else {
        // check for ".."
        if (strstr(req_path, "..")) {
        ta.resp_status = 404; // 
        send_response(&ta);
        rc = true;
        } else {
        rc = handle_static_asset(&ta, server_root);
        }
    }

    self->keep_alive = ta.want_keep_alive;
    buffer_delete(&ta.resp_headers);
    buffer_delete(&ta.resp_body);

    return rc;
}
