### **Detailed Academic Notes: Chapter 2 - The Application Layer**

***

### **2.1 Principles of Network Applications**

Network applications are the foundation of the internet, driving its widespread use and success[cite: 1]. They are composed of programs that run on different end systems and communicate with each other over the network[cite: 1]. It's crucial to understand that network application software is designed to run on end systems (hosts), not on network-core devices like routers or switches[cite: 1]. This design principle has facilitated the rapid development of a vast array of applications[cite: 1].

#### **2.1.1 Network Application Architectures**

The architecture of an application is distinct from the fixed, underlying network architecture[cite: 1]. Application developers choose from two primary paradigms: **Client-Server** and **Peer-to-Peer (P2P)**[cite: 1].

* **Client-Server Architecture:**
    * This architecture features an **always-on server** that provides services to many **clients**[cite: 1].
    * Clients do not communicate directly with each other[cite: 1].
    * The server has a fixed, well-known IP address, allowing clients to always find it[cite: 1].
    * Examples include the Web, FTP, and email[cite: 1].
    * To handle a large number of requests, a single server is often replaced by a **data center**, which houses a large number of hosts to create a powerful virtual server[cite: 1].

* **Peer-to-Peer (P2P) Architecture:**
    * This architecture relies minimally on dedicated servers[cite: 1].
    * Instead, it uses direct communication between intermittently connected hosts, called **peers**[cite: 1].
    * Peers are typically user-controlled desktops and laptops[cite: 1].
    * A key feature is **self-scalability**: as peers join the system and request files (generating workload), they also contribute to the system's capacity by distributing files to other peers[cite: 1].
    * P2P architectures are cost-effective as they don't require significant server infrastructure and bandwidth[cite: 1].
    * However, they face challenges in security, performance, and reliability due to their decentralized nature[cite: 1].

#### **2.1.2 Processes Communicating**

Within end systems, communication takes place between **processes**, which are programs that are currently running[cite: 1]. Processes on different hosts communicate by exchanging **messages**[cite: 1].

* **Client and Server Processes:**
    * In any communication session between two processes, one is designated as the **client process** and the other as the **server process**[cite: 1].
    * The **client process** is the one that initiates the communication[cite: 1].
    * The **server process** is the one that waits to be contacted[cite: 1].
    * For example, in a Web application, the browser is the client process, and the Web server is the server process because the browser initiates contact[cite: 1].
    * In a P2P file-sharing system, the peer that is downloading a file is the client, and the peer that is uploading the file is the server for that specific communication session[cite: 1]. A single process can be both a client and a server at different times[cite: 1].

* **The Interface: Sockets:**
    * A process sends and receives messages through a software interface called a **socket**[cite: 2].
    * The socket is the interface between the **application layer** and the **transport layer** within a host[cite: 2].
    * It's also known as the **Application Programming Interface (API)** for network communication[cite: 2].
    * The application developer controls the application-layer side of the socket, but has limited control over the transport-layer side, mainly choosing the transport protocol and some parameters like buffer size[cite: 2]. 
* **Addressing Processes:**
    * To send a message to a process on another host, two pieces of information are required: the **host's IP address** and a **port number** that identifies the specific process (or socket) on that host[cite: 2].
    * IP addresses uniquely identify a host[cite: 2].
    * Port numbers are used because a single host can run multiple network applications simultaneously[cite: 2]. For example, a Web server uses port 80, and a mail server uses port 25[cite: 2].

#### **2.1.3 Transport Services Available to Applications**

The socket is the interface where an application chooses a transport-layer protocol to use. The choice of protocol depends on the application's needs regarding four key service dimensions[cite: 2].

1.  **Reliable Data Transfer:**
    * Networks can lose or corrupt packets[cite: 3].
    * For applications like file transfer, email, or financial transactions, data loss is unacceptable[cite: 3].
    * A **reliable data transfer** service guarantees that data sent by the application will be delivered to the receiving process completely and without errors[cite: 3].
    * For loss-tolerant applications like real-time video or audio, an unreliable service may be acceptable as a small amount of data loss only causes a minor glitch[cite: 3].

2.  **Throughput:**
    * **Throughput** is the rate at which a sending process can deliver bits to a receiving process[cite: 3]. It can fluctuate over time as other sessions share the network's bandwidth[cite: 3].
    * A transport protocol can offer a **guaranteed available throughput** at a specified rate[cite: 3].
    * **Bandwidth-sensitive applications** (e.g., Internet telephony) require a guaranteed throughput[cite: 3].
    * **Elastic applications** (e.g., email, file transfer) can use as much or as little throughput as is available[cite: 3].

3.  **Timing:**
    * A transport protocol can provide **timing guarantees**, such as ensuring that every bit sent arrives at the receiver within a specified delay[cite: 3].
    * This is critical for **interactive real-time applications** like video conferencing and multiplayer games, where long delays make the experience unnatural[cite: 3].

4.  **Security:**
    * A transport protocol can provide security services such as **encryption**, which scrambles data to ensure confidentiality[cite: 3].
    * Other services include **data integrity** and **end-point authentication**[cite: 3].

#### **2.1.4 Transport Services Provided by the Internet**

The Internet provides two transport protocols for applications: **TCP** and **UDP**[cite: 4]. The choice between them depends on the application's specific service requirements[cite: 4].

* **TCP Services:**
    * **Connection-Oriented Service:** Before data transfer begins, TCP performs a **handshaking** procedure to establish a connection between the client and server[cite: 4]. This alerts the hosts to prepare for data flow and creates a **full-duplex** connection, allowing simultaneous two-way communication[cite: 4]. The connection must be torn down after the data transfer is complete[cite: 4].
    * **Reliable Data Transfer:** TCP guarantees that all data passed to it will be delivered to the receiving process without any errors, missing bytes, or duplicate bytes, and in the correct order[cite: 4].
    * **Congestion Control:** TCP includes a mechanism to throttle a sending process when the network is congested, ensuring the overall health of the network and providing a fair share of bandwidth to each connection[cite: 4].

* **UDP Services:**
    * UDP is a "no-frills, lightweight" protocol that provides minimal services[cite: 4].
    * It is **connectionless**, meaning there is no handshaking before communication begins[cite: 4].
    * It provides an **unreliable data transfer service**, offering no guarantee that a message will be delivered, and if it does, it may arrive out of order[cite: 4].

* **Securing TCP:**
    * Neither TCP nor UDP provides built-in encryption[cite: 4]. To address this, **Transport Layer Security (TLS)** was developed as an enhancement to TCP[cite: 4]. TLS is not a separate transport protocol but is implemented in the application layer[cite: 4]. It provides security services like encryption, data integrity, and end-point authentication[cite: 4].

***

### **2.2 The Web and HTTP**

The **World Wide Web** is a highly popular distributed application[cite: 5]. The Web's application-layer protocol is the **HyperText Transfer Protocol (HTTP)**[cite: 5].

#### **2.2.1 Overview of HTTP**

* HTTP is a request-response protocol where a **client (browser)** sends a request for a Web object and a **server** responds with the object[cite: 6].
* HTTP is a **stateless protocol**[cite: 7]. This means the server maintains no information about past client requests[cite: 7]. This design simplifies server implementation and allows servers to handle many simultaneous connections[cite: 7].
* HTTP uses **TCP** as its underlying transport protocol[cite: 6]. The client first initiates a TCP connection to the server[cite: 6].

#### **2.2.1.1 HTTP Message Format**

HTTP messages are in human-readable ASCII format and consist of two types: **request messages** and **response messages**.

**HTTP Request Message Format:**
```
Request line (method, URL, version)
Header lines
\r\n (blank line)
Entity body (optional)
```

**Example HTTP Request:**
```http
GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/xhtml+xml,application/xml
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate
Connection: keep-alive
```

**HTTP Response Message Format:**
```
Status line (version, status code, status phrase)
Header lines
\r\n (blank line)
Entity body
```

**Example HTTP Response:**
```http
HTTP/1.1 200 OK
Date: Mon, 27 Jul 2009 12:28:53 GMT
Server: Apache/2.2.14 (Win32)
Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT
Content-Length: 88
Content-Type: text/html
Connection: Closed

<html>
<body>
<h1>Hello World!</h1>
</body>
</html>
```

**Common HTTP Request Methods:**
* **GET:** Requests a resource from the server
* **POST:** Submits data to be processed by the server
* **PUT:** Uploads a resource to the server
* **DELETE:** Deletes a resource from the server
* **HEAD:** Requests only the headers (no body) of a resource

**Common HTTP Status Codes:**
* **200 OK:** Request succeeded
* **301 Moved Permanently:** Resource has been permanently moved
* **400 Bad Request:** Request syntax is malformed
* **404 Not Found:** Requested resource does not exist
* **505 HTTP Version Not Supported:** Server doesn't support the HTTP version

**Important HTTP Headers:**
* **Host:** Specifies the host and port number of the server
* **User-Agent:** Identifies the client software
* **Accept:** Specifies media types acceptable for the response
* **Content-Type:** Indicates the media type of the entity body
* **Content-Length:** Indicates the size of the entity body in bytes
* **Connection:** Controls whether the connection stays open after the transaction

#### **2.2.2 Non-Persistent and Persistent Connections**

* **Non-Persistent Connections:**
    * A separate TCP connection is created and then closed for each requested object on a Web page[cite: 8].
    * This process involves multiple rounds of TCP setup and teardown for a single page, which can be inefficient[cite: 8].
    * The typical sequence for a single object is:
        1.  Client initiates a TCP connection to the server on port 80[cite: 8].
        2.  Client sends an HTTP request message[cite: 8].
        3.  Server receives the request, retrieves the object, encapsulates it in an HTTP response message, and sends it to the client[cite: 8].
        4.  The server closes the TCP connection[cite: 8].
        5.  The client receives the response and the TCP connection terminates[cite: 8].
        6.  For a Web page with 10 images, this process is repeated 11 times (once for the HTML file and once for each image)[cite: 8].

* **Persistent Connections:**
    * A single TCP connection is used to send and receive multiple HTTP requests and responses[cite: 8].
    * The server leaves the connection open after sending a response[cite: 8].
    * Subsequent requests for objects on the same page are sent over this established connection, eliminating the need for repeated handshaking[cite: 8].

#### **2.2.3 Web Caching**

* A **Web cache** (or proxy server) is a network entity that can satisfy HTTP requests on behalf of an origin server[cite: 10].
* It has its own disk storage and is both a **server** (to the client) and a **client** (to the origin server)[cite: 10].
* **How it Works:**
    1.  A client browser is configured to send all HTTP requests to a Web cache[cite: 10].
    2.  The browser sends a request to the cache[cite: 10].
    3.  The cache checks if it has a stored copy of the requested object[cite: 10].
    4.  If the object is in the cache (**cache hit**), it is immediately sent back to the client[cite: 10]. This significantly reduces response time.
    5.  If the object is not in the cache (**cache miss**), the cache acts as a client, establishes a TCP connection to the origin server, and sends an HTTP request[cite: 10].
    6.  The origin server responds with the object[cite: 10].
    7.  The cache receives the object, stores a copy, and then sends a copy to the client[cite: 10].
* **Benefits:**
    * **Reduced Client Response Time:** When a request is satisfied by the cache, the response time is much shorter, especially if the bottleneck bandwidth is between the client and the origin server[cite: 10].
    * **Reduced Traffic on Access Link:** Caches reduce the amount of traffic on an institution's link to the Internet, saving bandwidth and cost[cite: 10].
    * **Reduced Internet Traffic:** Caches reduce overall Web traffic in the Internet, improving performance for all users[cite: 10].

#### **2.2.4 User-Server Interaction: Cookies**

* Although HTTP is stateless, many websites need to track user identity. They do this using **cookies**[cite: 9].
* A cookie system has four components:
    1.  A `Set-cookie:` header in the HTTP response message[cite: 9].
    2.  A `Cookie:` header in the HTTP request message[cite: 9].
    3.  A cookie file on the user's host, managed by the browser[cite: 9].
    4.  A back-end database at the Web site[cite: 9].
* **How it Works:**
    1.  The first time a user visits a site, the server creates a unique ID and an entry in its back-end database[cite: 9].
    2.  The server responds with a `Set-cookie:` header that includes this ID[cite: 9].
    3.  The client's browser receives this response, extracts the ID, and stores it in the user's cookie file, associating it with the server's domain[cite: 9].
    4.  For all subsequent requests to that server, the browser checks its cookie file, finds the ID, and includes a `Cookie:` header with this ID in the HTTP request[cite: 9].
    5.  The server uses the ID to retrieve the user's information from its database, effectively tracking the user's state across sessions[cite: 9].

***

### **2.3 Email and Simple Mail Transfer Protocol (SMTP)**

SMTP is the application-layer protocol for electronic mail. It is used to transfer email from a sender's mail server to a receiver's mail server. It is also used to transfer mail from a sender's host to the sender's mail server.

* **Core Components:** The email system consists of three main components:
    1.  **User Agents:** These are the clients for reading and composing emails (e.g., Gmail, Outlook).
    2.  **Mail Servers:** These servers store mailboxes for users and also act as SMTP clients and servers to send and receive messages.
    3.  **SMTP:** The protocol that transfers messages between mail servers.
* **Protocol Overview:**
    * SMTP uses a **persistent TCP connection** to transfer messages reliably.
    * It is a **push protocol**; the sending mail server pushes the email to the receiving mail server.
    * It operates in two phases: the **handshaking phase**, where the sender and receiver introduce themselves, and the **transfer phase**, where the message content is sent.
    * SMTP uses ASCII commands and responses. The commands are sent by the SMTP client (sender's mail server) to the SMTP server (receiver's mail server). The server replies with a status code and an optional message.
* **How it Works (Example):**
    1.  A user runs a user agent (e.g., Outlook) and composes an email to `johndoe@university.edu`.
    2.  The user agent sends the message to the user's mail server (e.g., a server at their ISP).
    3.  The user's mail server acts as the SMTP client and initiates a TCP connection to the destination mail server (the server for `university.edu`).
    4.  The two servers engage in an SMTP handshaking process, including the `HELO` and `MAIL FROM` commands from the client, and `220` and `250 OK` responses from the server.
    5.  The client sends the body of the message using the `DATA` command.
    6.  The server receives the message and stores it in John Doe's mailbox.
    7.  John Doe uses his user agent to retrieve the message from the mail server. This is typically done using a different protocol, such as IMAP or POP3.

#### **2.3.1 Mail Access Protocols: IMAP vs POP3**

While SMTP is used for sending email, users need different protocols to retrieve their email from mail servers. The two primary mail access protocols are **IMAP** and **POP3**.

| **Aspect** | **IMAP (Internet Message Access Protocol)** | **POP3 (Post Office Protocol v3)** |
|---|---|---|
| **Storage Model** | Messages remain on server | Messages downloaded to client |
| **Multi-device Access** | Excellent - sync across all devices | Poor - messages tied to one device |
| **Offline Access** | Limited - requires server connection | Full - all messages stored locally |
| **Storage Management** | Server manages storage | Client manages local storage |
| **Bandwidth Usage** | Higher - frequent server communication | Lower - one-time download |
| **Default Port** | 143 (unencrypted), 993 (SSL/TLS) | 110 (unencrypted), 995 (SSL/TLS) |
| **Folder Support** | Full server-side folder management | Limited folder support |
| **Search Capabilities** | Server-side search (faster for large mailboxes) | Client-side search only |
| **Backup** | Server handles backup | User responsible for backup |
| **Security** | Messages remain centrally managed | Local storage security risks |
| **Best Use Case** | Multiple devices, shared access | Single device, limited server storage |

***

### **File Transfer Protocol (FTP)**

FTP is the application-layer protocol used to transfer files to and from a remote host. It is built on a client-server architecture.

* **Key Features:**
    * FTP uses two parallel **TCP connections** to transfer a file:
        * **Control Connection:** This connection is used for sending control information, such as user identification, passwords, and commands to change directories. It is established first and remains open for the entire duration of the session.
        * **Data Connection:** This connection is used for the actual file transfer. A new data connection is opened for each file transferred and is closed after the file transfer is complete.
    * Because the control and data connections are separate, FTP is said to be an **out-of-band** protocol (control commands are sent in a separate connection from data).
* **Protocol Overview:**
    * The FTP client contacts the FTP server on port 21.
    * The client uses a simple command language over the control connection, such as `list` (to request a list of files in the current directory) and `retr` (to retrieve a file).
    * When a file transfer is requested, the client or server creates a new data connection on a different port.
    * After the file is transferred, the data connection is closed, but the control connection remains open for further commands.
* **How it Works (Example):**
    1.  A user invokes an FTP client, which initiates a control TCP connection with the FTP server on port 21.
    2.  The user sends login credentials over this connection.
    3.  The user issues a command, for example, `list` to see the files on the server.
    4.  The server opens a new TCP connection (the data connection) to send the file list back to the client.
    5.  The user issues a command to retrieve a file, `retr filename`.
    6.  The server opens a new data connection to transfer the file's contents.
    7.  The file is transferred, and the data connection is closed.
    8.  The control connection remains open until the user issues a `quit` command, at which point both connections are closed.

### **2.4 DNS - The Internet’s Directory Service**

The **Domain Name System (DNS)** is a core Internet function that translates human-readable hostnames (e.g., `www.amazon.com`) into computer-friendly IP addresses[cite: 12].

#### **2.4.1 The DNS Service**

* DNS is both a **distributed database** and an **application-layer protocol**[cite: 12].
* The DNS protocol runs over **UDP** and uses port 53[cite: 13].
* DNS is used by other application-layer protocols like HTTP and SMTP to obtain IP addresses for hostnames[cite: 12].
* A centralized DNS server would fail due to:
    * **Single point of failure:** A server crash would take down the entire Internet[cite: 13].
    * **Traffic volume:** A single server could not handle all the DNS queries[cite: 13].
    * **Distant centralized database:** Queries from distant locations would experience significant delays[cite: 13].
    * **Maintenance:** A single database would be massive and difficult to update[cite: 13].
* Therefore, DNS is designed as a **distributed, hierarchical database**[cite: 13].

#### **2.4.2 A Distributed, Hierarchical Database**

The DNS hierarchy consists of several classes of servers[cite: 13]:

* **Root DNS Servers:** At the top of the hierarchy, these servers know the addresses of the TLD servers[cite: 13].
* **Top-Level Domain (TLD) Servers:** There are TLD servers for each top-level domain (e.g., `.com`, `.org`, `.edu`). They know the authoritative DNS servers for all domains within their TLD[cite: 13].
* **Authoritative DNS Servers:** Every organization with public hosts (like Web or mail servers) must have an authoritative DNS server that contains the DNS records mapping the hostnames to IP addresses[cite: 13].
* **Local DNS Servers:** An ISP (residential or institutional) has a local DNS server that does not belong to the main hierarchy but is central to the DNS process[cite: 13]. A host's local DNS server is typically its "first stop" for any DNS query[cite: 13].

#### **2.4.3 DNS Resolution Process: How it works**

There are two types of DNS queries:

* **Iterative Query:**
    * The local DNS server sends a query to the root DNS server[cite: 13].
    * The root server replies with the address of the relevant TLD server[cite: 13].
    * The local DNS server then queries the TLD server, which replies with the address of the authoritative DNS server[cite: 13].
    * The local DNS server queries the authoritative server, which finally replies with the IP address of the requested host[cite: 13].
* **Recursive Query:**
    * The local DNS server sends a query to the root DNS server[cite: 13].
    * The root server then takes on the role of a client, sending a query to the TLD server on behalf of the local DNS server[cite: 13].
    * The TLD server then queries the authoritative DNS server[cite: 13].
    * The authoritative server replies to the TLD, which replies to the root, which then replies to the local DNS server with the final IP address[cite: 13].

Most DNS servers are configured to handle both types of queries. In practice, local DNS servers typically use iterative queries to communicate with the hierarchy, but can handle recursive queries from their local hosts.

#### **2.4.4 DNS Resource Records**

DNS servers store **resource records (RRs)**. Each RR is a four-tuple: `(Name, Value, Type, TTL)`[cite: 14].

* **Type A:** `(Hostname, IP Address, A, TTL)` - Maps a hostname to an IP address[cite: 14].
* **Type NS:** `(Domain Name, Hostname of Authoritative Server, NS, TTL)` - Gives the hostname of an authoritative DNS server that can get IP addresses for hosts within a given domain[cite: 15].
* **Type CNAME:** `(Alias Hostname, Canonical Hostname, CNAME, TTL)` - Provides an alias for a canonical hostname[cite: 14]. This is often used to map a server name to a content delivery network (CDN) hostname.
* **Type MX:** `(Domain Name, Canonical Hostname of Mail Server, MX, TTL)` - Gives the canonical hostname of a mail server for a specific domain[cite: 14].

#### **2.4.5 DNS in Practice**

When a new company, `networkutopia.com`, wants to go online, they must register their domain name with a **domain name registrar**[cite: 15]. The registrar will then insert the necessary NS and A records into the TLD servers to point to the company's own authoritative DNS server[cite: 15]. The company's authoritative server will then contain the A records for its Web servers and the MX records for its mail servers[cite: 15]. This ensures that when someone tries to access `www.networkutopia.com`, the DNS system can correctly translate the name to the appropriate IP address[cite: 15].

***

### **2.7 Socket Programming**

Socket programming is the process of writing network applications that use the **socket API** to send and receive data[cite: 16]. The API provides the programmer with a way to create and manage sockets, which act as the communication endpoints between processes. The text provides a detailed walkthrough of simple client-server applications using both TCP and UDP.

* **TCP Socket Programming:** The program must first establish a connection-oriented socket (using `socket.SOCK_STREAM` in Python). The client and server processes must then go through a three-way handshake before they can start sending data[cite: 4]. The TCP socket guarantees that the data will be delivered reliably and in order[cite: 4].
* **UDP Socket Programming:** The program creates a connectionless socket (using `socket.SOCK_DGRAM` in Python). There is no handshaking, so the processes can immediately send data[cite: 4]. However, the UDP socket offers no guarantees of reliability or ordering[cite: 4].

#### **2.7.1 TCP Socket Programming in C**

**TCP Server Example:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    
    // 1. Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // 2. Set up server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // 3. Bind socket to address
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    // 4. Listen for connections (max 5 pending connections)
    if (listen(server_fd, 5) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    printf("Server listening on port %d\n", PORT);
    
    // 5. Accept client connection
    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("Accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    printf("Client connected from %s:%d\n", 
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    
    // 6. Receive and echo data
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytes_received <= 0) {
            printf("Client disconnected\n");
            break;
        }
        
        printf("Received: %s", buffer);
        
        // Echo back to client
        send(client_fd, buffer, bytes_received, 0);
    }
    
    // 7. Close sockets
    close(client_fd);
    close(server_fd);
    return 0;
}
```

**TCP Client Example:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int client_fd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char message[BUFFER_SIZE];
    
    // 1. Create socket
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // 2. Set up server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    
    // Convert IP address from text to binary
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    
    // 3. Connect to server
    if (connect(client_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    
    printf("Connected to server\n");
    
    // 4. Send and receive data
    while (1) {
        printf("Enter message (or 'quit' to exit): ");
        fgets(message, BUFFER_SIZE, stdin);
        
        if (strncmp(message, "quit", 4) == 0) {
            break;
        }
        
        // Send message to server
        send(client_fd, message, strlen(message), 0);
        
        // Receive echo from server
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytes_received > 0) {
            printf("Server echo: %s", buffer);
        }
    }
    
    // 5. Close socket
    close(client_fd);
    return 0;
}
```

#### **2.7.2 UDP Socket Programming in C**

**UDP Server Example:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    
    // 1. Create UDP socket
    server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // 2. Set up server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // 3. Bind socket to address
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    printf("UDP Server listening on port %d\n", PORT);
    
    // 4. Receive and echo data (no connection needed)
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        
        // Receive data from client
        int bytes_received = recvfrom(server_fd, buffer, BUFFER_SIZE - 1, 0,
                                     (struct sockaddr*)&client_addr, &client_len);
        
        if (bytes_received > 0) {
            printf("Received from %s:%d: %s", 
                   inet_ntoa(client_addr.sin_addr), 
                   ntohs(client_addr.sin_port), buffer);
            
            // Echo back to client
            sendto(server_fd, buffer, bytes_received, 0,
                   (struct sockaddr*)&client_addr, client_len);
        }
    }
    
    // 5. Close socket
    close(server_fd);
    return 0;
}
```

**UDP Client Example:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int client_fd;
    struct sockaddr_in server_addr;
    socklen_t server_len = sizeof(server_addr);
    char buffer[BUFFER_SIZE];
    char message[BUFFER_SIZE];
    
    // 1. Create UDP socket
    client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (client_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // 2. Set up server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    
    // Convert IP address from text to binary
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    
    printf("UDP Client ready\n");
    
    // 3. Send and receive data (no connection needed)
    while (1) {
        printf("Enter message (or 'quit' to exit): ");
        fgets(message, BUFFER_SIZE, stdin);
        
        if (strncmp(message, "quit", 4) == 0) {
            break;
        }
        
        // Send message to server
        sendto(client_fd, message, strlen(message), 0,
               (struct sockaddr*)&server_addr, server_len);
        
        // Receive echo from server
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recvfrom(client_fd, buffer, BUFFER_SIZE - 1, 0,
                                     (struct sockaddr*)&server_addr, &server_len);
        
        if (bytes_received > 0) {
            printf("Server echo: %s", buffer);
        }
    }
    
    // 4. Close socket
    close(client_fd);
    return 0;
}
```

#### **2.7.3 Key Differences Between TCP and UDP Socket Programming**

* **Connection Management:**
    * **TCP:** Requires `listen()`, `accept()` on server side and `connect()` on client side to establish connection
    * **UDP:** No connection establishment; can immediately send/receive data

* **Data Transfer Functions:**
    * **TCP:** Uses `send()` and `recv()` functions
    * **UDP:** Uses `sendto()` and `recvfrom()` functions with address information

* **Reliability:**
    * **TCP:** Guarantees delivery, order, and error checking
    * **UDP:** No guarantees; faster but less reliable

* **Socket Type:**
    * **TCP:** `SOCK_STREAM` - connection-oriented, reliable
    * **UDP:** `SOCK_DGRAM` - connectionless, unreliable

**Compilation:** Compile these programs using: `gcc -o server server.c` and `gcc -o client client.c`