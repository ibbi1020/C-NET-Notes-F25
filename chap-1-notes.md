### **Detailed Academic Notes: Chapter 1 - Computer Networks and the Internet**

***

### **1.1 What Is the Internet?**

The Internet can be described through its foundational components or by the services it enables.

#### **1.1.1 A Nuts-and-Bolts Description**

The Internet is a massive, interconnected system of hardware and software.

* **Hosts (End Systems):** These are the devices that users interact with, such as computers, smartphones, and IoT devices. They are the sources and destinations of data.
* **Communication Links:** These are the physical media that carry data, characterized by their **transmission rate** or **bandwidth**. The higher the bandwidth, the more data can be transmitted per second.
* **Packet Switches:** These are the core networking devices that receive and forward data. **Routers** are used in the network core, while **link-layer switches** are typically used in local access networks.
* **How Data Moves:** When a host sends data, it first breaks the data into smaller units called **packets**. Each packet contains a portion of the data along with a header that includes a destination address. These packets are then sent through a series of packet switches along a **route** or **path** until they reach the destination host, where they are reassembled into the original data.
* **Protocols:** The entire process is governed by **protocols**, which are the rules of communication. The most famous is the **TCP/IP** suite. These protocols ensure that different devices from different manufacturers can all communicate with each other. Standards for these protocols are defined in documents called **Requests for Comments (RFCs)** by the **Internet Engineering Task Force (IETF)**.

#### **1.1.2 A Services Description**

From a services perspective, the Internet is an infrastructure for **distributed applications**. These applications, like web browsing and video streaming, are designed to run on multiple end systems and communicate with each other. The **socket interface** is the programming interface that provides a standard way for an application to send and receive data from another application on a different host. It's like a standardized API for network communication.

***

### **1.2 The Network Edge**

The network edge is where end systems and applications reside.

* **Clients and Servers:** End systems can act as **clients** (requesting services) or **servers** (providing services). In a web context, a web browser is a client and a web server is a server.

#### **1.2.1 Access Networks**

An **access network** is the physical network that connects a host to the Internet's first-hop router.

* **DSL (Digital Subscriber Line):** This technology uses the existing twisted-pair telephone line to connect to a telephone company's (telco) Central Office (CO). It uses different frequency bands for data and voice, allowing for simultaneous use. The **asymmetric** nature means that data travels faster from the telco to the home (downstream) than from the home to the telco (upstream).
* **Cable Internet Access:** Utilizes the same coaxial cable infrastructure as cable television. Data is transmitted on a different frequency band from television signals. Like DSL, it is **asymmetric** and the bandwidth is shared among multiple homes in a neighborhood, which can lead to reduced performance during peak usage times. A **Cable Modem Termination System (CMTS)** at the cable head end is the interface between the cable network and the Internet.
* **FTTH (Fiber to the Home):** This provides a direct optical fiber connection from a telco's CO to a home. It is a dedicated, high-speed connection. In a **Passive Optical Network (PON)** architecture, a single fiber from the CO is split to serve many homes, but they all share the optical signal.
* **Wireless and Wired LANs:**
    * **Ethernet:** A very common wired access technology. A host connects to an **Ethernet switch** using twisted-pair copper wire. The switch then connects to the edge router.
    * **Wi-Fi:** A wireless LAN standard (IEEE 802.11). End systems connect to a **wireless access point** using radio signals. The access point is in turn connected to the wired network, providing Internet access.

***

### **1.3 The Network Core**

The network core is the complex mesh of interconnected routers that form the Internet's backbone. It is a "network of networks" primarily using **packet switching**.

#### **1.3.1 Packet Switching**

The Internet uses packet switching because it is highly efficient for the "bursty" nature of data traffic.

* **Store-and-Forward Transmission:** This is a crucial concept. A router must first receive an entire packet and store it in a buffer before it can begin transmitting the first bit of that packet onto the next outgoing link. The time it takes to push the packet onto the link is the **transmission delay**.
* **Queuing and Loss:** When multiple packets arrive at a router destined for the same output link, they must wait in a **queue (buffer)**. The time a packet waits is its **queuing delay**. If the buffer is full when a new packet arrives, the packet will be dropped, a condition known as **packet loss**.

#### **1.3.2 Circuit Switching**

Circuit switching, used in traditional telephone networks, works differently.

* **Resource Reservation:** Before a communication session begins, a dedicated end-to-end circuit is reserved. This means that a fixed amount of bandwidth is allocated for the entire duration of the call.
* **Multiplexing:** The two methods for sharing a link's bandwidth are:
    * **Frequency Division Multiplexing (FDM):** The link's total bandwidth is divided into separate frequency bands, with each circuit assigned a unique band.
    * **Time Division Multiplexing (TDM):** The link's transmission time is divided into a repeating sequence of time slots. Each circuit is assigned a fixed time slot in each frame.

Circuit switching guarantees performance but is inefficient for bursty data because the reserved resources are idle during periods of silence.

***

### **1.4 Delay, Loss, and Throughput**

**End-to-end delay** is the total time from when a packet is sent from the source to when it is received at the destination. It is a sum of four key delays at each router:

1.  **Nodal Processing Delay ($d_{proc}$):** The time a router takes to read the packet's header and determine the correct output link. This is usually very short.
2.  **Queuing Delay ($d_{queue}$):** The time a packet waits in the output queue. This delay is highly variable and depends on the level of congestion. It is the only delay that is not fixed for a given path and packet.
3.  **Transmission Delay ($d_{trans}$):** This is the time it takes to "push" all of the packet's bits onto the link. It depends on the packet's size (L) and the link's transmission rate (R).
    * **Formula:** $d_{trans} = L / R$ 
4.  **Propagation Delay ($d_{prop}$):** The time it takes for a bit to travel from the beginning of the link to the next router. It depends on the distance of the link (d) and the propagation speed (s).
    * **Formula:** $d_{prop} = d / s$ 

**Packet Loss:** This occurs when a router's buffer is full and cannot store an incoming packet. The packet is simply dropped.

**Throughput:** This is the rate at which data is actually transferred.
* **Bottleneck Link:** The link on the end-to-end path with the lowest transmission rate. This link will limit the overall throughput of the connection. For example, if a path has links of 10 Mbps, 50 Mbps, and 100 Mbps, the bottleneck is the 10 Mbps link, and the maximum throughput cannot exceed this rate.

***

### **1.5 Protocol Layers and Their Service Models**

Network communication is organized into a layered **protocol stack** to simplify design and manage complexity. The Internet uses a five-layer model:

1.  **Application Layer:** The top layer, where user-facing applications run. Protocols like HTTP, FTP, and SMTP define how applications exchange data.
    * **Process:** An application creates a **message** and passes it down to the transport layer.
2.  **Transport Layer:** This layer is responsible for transporting application-layer messages between the sending and receiving processes.
    * **TCP (Transmission Control Protocol):** A reliable, **connection-oriented** protocol. It establishes a connection before data transfer, provides flow control (to prevent the sender from overwhelming the receiver), and congestion control (to prevent the network from becoming overloaded). It retransmits lost segments to ensure reliability.
    * **UDP (User Datagram Protocol):** An unreliable, **connectionless** protocol. It sends a **datagram** without establishing a connection and offers no guarantees of delivery.
    * **Process:** The transport layer takes the message from the application layer, adds a transport header (containing port numbers for process identification), and creates a **segment**. This segment is then passed to the network layer.
3.  **Network Layer:** Responsible for moving **datagrams** from the sending host to the receiving host. The core protocol is **IP (Internet Protocol)**, which defines the datagram format and addressing.
    * **Process:** The network layer takes the segment from the transport layer, adds an IP header (containing IP addresses), and creates a **datagram**. It then determines the best path for the datagram to travel across the network.
4.  **Link Layer:** This layer is responsible for moving a **datagram** from one node to the next. The protocols (e.g., Ethernet, Wi-Fi) depend on the specific link medium.
    * **Process:** The link layer encapsulates the datagram within a **frame**, adding a link-layer header. The frame is then passed to the physical layer.
5.  **Physical Layer:** This is the lowest layer, responsible for the physical transmission of individual bits within a frame.
    * **Process:** The physical layer takes the frame and converts its bits into electrical or optical signals to be transmitted over the physical medium.

**Encapsulation:** This is the process of adding headers as a packet moves down the protocol stack. At each layer, the protocol adds its own header, creating a new, larger packet. The reverse process, **decapsulation**, happens at the receiving host, where each layer strips off its header.

***

### **1.6 Security in Computer Networks**

* **Malware:** Malicious software that can damage or take control of a host.
    * **How it Works:** Malware can spread through **viruses** (that require a user to interact with an infected object, like an email attachment) or **worms** (which can self-replicate and spread without user interaction).
* **Denial-of-Service (DoS) Attacks:** These attacks aim to make a network service unavailable to legitimate users.
    * **Vulnerability Attack:** The attacker sends a few well-crafted packets that exploit a known bug in a target application or operating system, causing it to crash.
    * **Bandwidth Flooding:** The attacker sends a massive flood of traffic to the target, consuming the network bandwidth and preventing legitimate traffic from getting through.
    * **Connection Flooding:** The attacker bombards a server with a large number of bogus connection requests, exhausting the server's resources and preventing it from accepting legitimate connections.
* **Distributed Denial-of-Service (DDoS) Attack:** This is a more powerful form of a DoS attack.
    * **How it Works:** An attacker compromises many hosts (creating a **botnet**) and then coordinates all of them to simultaneously send a flood of traffic to a single target. This makes it much harder to block the attack by simply filtering traffic from a single source.
* **Packet Sniffing:** A passive attack where an attacker listens in on a shared communication medium (like a wireless network) and captures all the packets being transmitted.
    * **How it Works:** The attacker's network interface card is put into "promiscuous" mode, allowing it to read every packet, even if it is not addressed to the sniffer's machine. This can expose unencrypted passwords and other sensitive data.
* **IP Spoofing:** An attacker sends packets with a forged source IP address to masquerade as another user.
    * **How it Works:** The attacker's software simply places a fake source address in the packet header before sending it. This can be used to bypass security filters that rely on the source IP address. It is often used in DoS attacks to hide the attacker's true identity.