
# Personal Server
PROJECT OVERVIEW

Personal Server is a secure and efficient HTTP server developed as part of the CS 3214 "Personal Secure Server" project. This repository serves as the foundational codebase, implementing essential HTTP/1.0 functionalities with enhancements for security and performance. The server supports key HTTP methods, manages user authentication using JSON Web Tokens (JWT), and provides API endpoints for login, logout, and video retrieval. Designed with security in mind, it incorporates measures to prevent common vulnerabilities such as path traversal and indirect object reference (IDOR) attacks.

FEATURES

- **HTTP Method Support:** Implements essential HTTP methods including GET and POST, enabling basic client-server interactions.
- **Static File Serving:** Efficiently serves static assets like HTML, CSS, JavaScript, images, and videos from the server's root directory.
- **JWT-Based Authentication:** Utilizes JSON Web Tokens (JWT) for secure user authentication, managing login and logout processes through API endpoints.
- **API Endpoints:** Provides `/api/login`, `/api/logout`, and `/api/video` endpoints to handle user authentication and video file retrieval.
- **Range Requests:** Supports byte-range requests for media files, allowing partial content delivery for efficient streaming.
- **Security Measures:** Implements checks to prevent path traversal and IDOR attacks, ensuring that users can only access authorized resources.
- **MIME Type Handling:** Dynamically determines and sets appropriate MIME types for served files based on their extensions.
- **Error Handling:** Robust error responses for various HTTP status codes, enhancing client feedback and debugging.
- **HTML5 Fallback:** Supports HTML5 fallback mechanisms to handle single-page application routing and resource serving.

DATA STRUCTURES USED

**Buffer Management:**

buffer_t: A dynamic buffer structure used for constructing and managing HTTP response headers and bodies. It ensures efficient memory usage and facilitates easy appending of data.

**HTTP Transaction Handling:**

http_transaction: A structure that encapsulates all aspects of an HTTP transaction, including request method, path, version, headers, body, and response details. It serves as the central point for processing and responding to client requests.

**JWT Handling:**

jwt_t: Utilizes the libjwt library to create, decode, and validate JSON Web Tokens. This structure manages authentication tokens, ensuring secure communication between clients and the server.

DESIGN CONSIDERATIONS

- **Security First:** Prioritized the implementation of security measures to protect against common web vulnerabilities. This includes validating and sanitizing user inputs, enforcing strict access controls, and securely managing authentication tokens.
- **Modular Architecture:** Designed the server with modularity in mind, separating concerns such as request parsing, header processing, response generation, and API handling. This facilitates easier maintenance and future feature expansions.
- **Performance Optimization:** Implemented efficient file serving mechanisms, including support for range requests and the use of `sendfile` for zero-copy data transfers, enhancing the server's performance and scalability.
- **Extensibility:** Structured the code to allow easy addition of new features and endpoints. The handling of API routes is centralized, making it straightforward to introduce new functionalities without disrupting existing ones.
- **Compliance with HTTP Standards:** Ensured that the server adheres to HTTP/1.0 and HTTP/1.1 standards, providing appropriate responses and headers based on client requests. This guarantees compatibility with a wide range of clients and browsers.
- **Error Handling and Logging:** Implemented comprehensive error handling to provide meaningful feedback to clients and facilitate debugging. Logging mechanisms can be integrated to monitor server activities and diagnose issues effectively.

REPOSITORY STRUCTURE

- **src:** Contains the base code's source files.
- **tests:** Contains unit tests, performance tests, and associated files.
- **svelte-app:** Contains a JavaScript web app.
- **sfi:** Contains documentation for the 'server fuzzing interface'.
  
CONCLUSION

The Personal Server project offers a robust and secure HTTP server implementation tailored for educational purposes in the CS 3214 course. By integrating advanced data structures like Buffer Management and JWT Handling, it ensures efficient data management and secure user interactions. The emphasis on security, modularity, and performance makes it not only a valuable learning tool but also a solid foundation for further development and real-world application. Whether used for coursework, experimentation, or as a stepping stone for more complex server projects, Personal Server demonstrates the essential principles of reliable and secure server design.


