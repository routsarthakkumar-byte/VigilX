# 🛡️ VigilX

### Cybersecurity Threat Simulation & Security Operations Engine

> **A C++ Object-Oriented Cybersecurity Simulation Platform for Threat Modeling, Detection, Response and Security Operations**

---

## 📌 Overview

**VigilX** is a controlled cybersecurity simulation platform developed in **C++ using Object-Oriented Programming (OOP)**.

The system creates a virtual organizational security environment containing:

* 👤 Users
* 🖥️ Digital Resources
* 🔐 Authentication Systems
* 🛂 Access Control Policies
* ⚠️ Simulated Cyber Threats
* 🔎 Threat Detection
* 🚨 Incident Response
* 📜 Security Logs
* 📊 Security Analytics

VigilX does **not** perform real cyber attacks. Instead, it simulates realistic security scenarios inside a controlled virtual environment to demonstrate how a security operations system can **detect, analyze, respond to and record security incidents**.

---

# 🎯 Project Objective

The main objective of VigilX is to demonstrate how **Object-Oriented Programming can be applied to a real-world cybersecurity system**.

The system is designed to:

1. Manage different types of users.
2. Manage protected digital resources.
3. Authenticate users.
4. Implement Role-Based Access Control (RBAC).
5. Simulate different cybersecurity threats.
6. Detect suspicious activities.
7. Classify threats according to severity.
8. Automatically respond to incidents.
9. Maintain security logs.
10. Generate security statistics and reports.

---

# 🧠 Core Concept

VigilX follows a complete security-operation lifecycle:

```text
              ┌───────────────────┐
              │   Virtual Users   │
              └─────────┬─────────┘
                        │
                        ↓
              ┌───────────────────┐
              │ Authentication    │
              └─────────┬─────────┘
                        │
                        ↓
              ┌───────────────────┐
              │ Access Control    │
              │      (RBAC)       │
              └─────────┬─────────┘
                        │
                        ↓
              ┌───────────────────┐
              │ Threat Simulation │
              └─────────┬─────────┘
                        │
                        ↓
              ┌───────────────────┐
              │ Threat Detection  │
              └─────────┬─────────┘
                        │
                        ↓
              ┌───────────────────┐
              │ Threat Analysis   │
              └─────────┬─────────┘
                        │
                        ↓
              ┌───────────────────┐
              │ Incident Response │
              └─────────┬─────────┘
                        │
                        ↓
              ┌───────────────────┐
              │ Security Logging  │
              └─────────┬─────────┘
                        │
                        ↓
              ┌───────────────────┐
              │ Security Reports  │
              └───────────────────┘
```

### Complete Workflow

```text
SIMULATE
   ↓
DETECT
   ↓
ANALYZE
   ↓
CLASSIFY
   ↓
RESPOND
   ↓
LOG
   ↓
REPORT
```

---

# 🔐 Main Features

## 1. User Management

VigilX supports multiple user roles:

```text
User
 ├── Admin
 ├── Employee
 ├── Guest
 └── SecurityAnalyst
```

Each user contains information such as:

* User ID
* Username
* Password
* Role
* Account Status
* Failed Login Attempts
* Permissions

The system allows administrators to:

* Add users
* Remove users
* Search users
* Modify users
* Change roles
* View user information
* Lock/unlock accounts

---

# 🖥️ 2. Resource Management

VigilX contains different types of protected resources:

```text
Resource
 ├── Database
 ├── Server
 ├── File
 ├── API
 └── AdminPanel
```

Each resource can have different security requirements.

For example:

```text
Guest
   ↓
Public File       → ✅ Allowed

Guest
   ↓
Employee Database → ❌ Denied

Guest
   ↓
Admin Panel       → ❌ Denied
```

---

# 🔑 3. Authentication System

VigilX provides a simulated authentication system.

Example:

```text
Username: john
Password: ****

Authenticating...

✓ Username Found
✓ Password Verified

LOGIN SUCCESSFUL
```

Repeated failed attempts can trigger security mechanisms.

Example:

```text
Login Attempt 1 ❌
Login Attempt 2 ❌
Login Attempt 3 ❌
Login Attempt 4 ❌
Login Attempt 5 ❌

🚨 SUSPICIOUS LOGIN ACTIVITY
```

---

# 🛂 4. Role-Based Access Control

VigilX implements **RBAC (Role-Based Access Control)**.

Example permission model:

| Role             | Database   | Public Files | Admin Panel | Security Monitoring |
| ---------------- | ---------- | ------------ | ----------- | ------------------- |
| Admin            | ✅          | ✅            | ✅           | ✅                   |
| Employee         | ✅          | ✅            | ❌           | ❌                   |
| Guest            | ❌          | ✅            | ❌           | ❌                   |
| Security Analyst | Monitoring | ✅            | ❌           | ✅                   |

Whenever a user attempts to access a resource, VigilX checks:

```text
User
 ↓
User Role
 ↓
Security Policy
 ↓
Resource Permission
 ↓
ALLOW / DENY
```

---

# ⚠️ 5. Threat Simulation Engine

VigilX can simulate different cybersecurity scenarios.

### Supported Threats

* 🔨 Brute Force Attack
* 🚫 Unauthorized Access
* 🔑 Suspicious Login
* ⬆️ Privilege Escalation
* 📂 Abnormal Resource Access
* 🧩 Custom Security Scenarios

Example:

```text
==========================================
           VIGILX THREAT SIMULATOR
==========================================

1. Brute Force Attack
2. Unauthorized Access
3. Suspicious Login
4. Privilege Escalation
5. Abnormal Resource Access
6. Custom Scenario

Choose Threat:
```

---

# 🔨 Example: Brute Force Simulation

```text
Target Account: john

Login Attempt 1 ❌
Login Attempt 2 ❌
Login Attempt 3 ❌
Login Attempt 4 ❌
Login Attempt 5 ❌

==========================================
🚨 BRUTE FORCE ATTACK DETECTED
==========================================

Severity : HIGH

Response:
→ Account Locked
→ Further Attempts Blocked
→ Security Alert Generated
→ Incident Logged
```

---

# 🚫 Example: Unauthorized Access

```text
User: Guest

Requested Resource:
Admin Database

Checking RBAC Policy...

❌ ACCESS DENIED

Analyzing Activity...

🚨 UNAUTHORIZED ACCESS DETECTED

Severity: HIGH

Response:
→ Access Blocked
→ Alert Generated
→ Incident Logged
```

---

# ⬆️ Example: Privilege Escalation

```text
User Role: Guest

Request:
Administrator Privileges

Checking Security Policy...

❌ INVALID PRIVILEGE REQUEST

🚨 PRIVILEGE ESCALATION DETECTED

Severity: CRITICAL

Response:
→ Request Blocked
→ User Flagged
→ Security Alert Generated
→ Incident Logged
```

---

# 🔎 6. Threat Detection Engine

The **Threat Detection Engine** analyzes simulated security events.

It looks for patterns such as:

* Repeated failed logins
* Unauthorized resource access
* Abnormal access patterns
* Invalid privilege requests
* Suspicious user activity

Threats are classified as:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

---

# 🚨 7. Incident Response Engine

Once a threat is detected, VigilX can automatically perform defensive actions.

Possible responses:

```text
BLOCK ACCESS
LOCK ACCOUNT
DENY REQUEST
FLAG USER
GENERATE ALERT
LOG INCIDENT
```

Example:

```text
Threat Detected
      ↓
Threat Severity Analysis
      ↓
Response Engine
      ↓
┌──────────────────────┐
│ Account Locked       │
│ Access Blocked       │
│ Alert Generated      │
│ Incident Logged      │
└──────────────────────┘
```

---

# 📜 8. Security Logging

Every important security event is recorded.

Example:

```text
[2026-09-08 10:31:22]
User: john
Event: Failed Login
Severity: MEDIUM

[2026-09-08 10:31:28]
User: john
Event: Brute Force Detected
Severity: HIGH

[2026-09-08 10:31:29]
Response: Account Locked
```

Logs can be stored using C++ file handling.

---

# 📊 9. Security Statistics

VigilX can generate security statistics such as:

```text
==========================================
             VIGILX SECURITY REPORT
==========================================

Total Users              : 25
Total Resources          : 12

Threats Detected         : 17
Low Severity             : 5
Medium Severity          : 4
High Severity            : 6
Critical Severity        : 2

Blocked Requests         : 14
Locked Accounts          : 3

Security Score           : 82/100
==========================================
```

---

# 🧩 Object-Oriented Programming

VigilX is primarily designed around **OOP principles**.

## 1. Classes

Major classes include:

```text
User
Admin
Employee
Guest
SecurityAnalyst

Resource
Database
Server
File
API
AdminPanel

Threat
BruteForceAttack
UnauthorizedAccess
SuspiciousLogin
PrivilegeEscalation

ThreatDetector
SecurityPolicy
ResponseEngine
Logger
SecurityEngine
```

---

# 🔒 2. Encapsulation

Sensitive information is kept private.

Example:

```cpp
class User {
private:
    string username;
    string password;
    int failedAttempts;
    bool accountLocked;

public:
    bool login(string password);
    void lockAccount();
    void resetAttempts();
};
```

The internal security data cannot be directly modified from outside the class.

---

# 🧱 3. Inheritance

VigilX uses inheritance to represent different types of users and threats.

### User Hierarchy

```text
              User
               │
       ┌───────┼────────┐
       ↓       ↓        ↓
     Admin  Employee   Guest
```

### Threat Hierarchy

```text
                 Threat
                   │
       ┌───────────┼────────────┐
       ↓           ↓            ↓
 BruteForce   Unauthorized   Suspicious
   Attack        Access        Login
                   │
                   ↓
          PrivilegeEscalation
```

---

# 🎭 4. Polymorphism

The base `Threat` class can define a virtual function:

```cpp
virtual void simulate() = 0;
```

Each derived threat implements its own behavior:

```cpp
BruteForceAttack
        ↓
simulate()

UnauthorizedAccess
        ↓
simulate()

PrivilegeEscalation
        ↓
simulate()
```

This allows VigilX to process different threats through a common interface.

---

# 🧠 5. Abstraction

Complex internal security logic is hidden behind simple interfaces.

For example:

```cpp
threat.simulate();
```

The user does not need to know how the threat is internally simulated.

Similarly:

```cpp
detector.analyze();
response.execute();
logger.record();
```

provide high-level security operations.

---

# 🔁 6. Function Overloading

VigilX can demonstrate function overloading.

Example:

```cpp
login(username, password);

login(userID, password);

login(username, password, otp);
```

Same operation, different parameters.

---

# 🔄 7. Function Overriding

Derived threat classes override the behavior of the base class.

```cpp
class Threat {
public:
    virtual void simulate() = 0;
};
```

Derived classes provide their own implementation.

---

# 🧰 STL Usage

VigilX makes use of C++ STL containers.

### Vector

```cpp
vector<User> users;
vector<Resource> resources;
vector<Threat*> threats;
```

### Unordered Map

Used for fast lookup:

```cpp
unordered_map<string, User> userDatabase;
```

### Queue

Used for pending security events:

```cpp
queue<SecurityEvent> eventQueue;
```

### Map

Used for threat statistics:

```cpp
map<Severity, int> threatCount;
```

---

# ⚡ Exception Handling

VigilX handles invalid operations using C++ exception handling.

Examples:

```text
Invalid Username
Invalid Password
Invalid Resource
Invalid Role
Unauthorized Access
Invalid Threat
Invalid Input
```

Example:

```cpp
try {
    securityEngine.accessResource(user, resource);
}
catch (exception& e) {
    cout << e.what();
}
```

---

# 💾 File Handling

VigilX uses C++ file handling to maintain persistent information.

Example files:

```text
users.txt
resources.txt
policies.txt
security_logs.txt
```

Technologies:

```cpp
ifstream
ofstream
fstream
```

This allows security logs and system data to remain available after the program terminates.

---

# 🏗️ Design Patterns

To make the project more advanced, VigilX can incorporate suitable design patterns.

### Singleton

Used for the central security engine.

```text
VigilX SecurityEngine
        ↓
Single Central Controller
```

### Factory Pattern

Used to create different threat objects.

```text
ThreatFactory
     │
     ├── BruteForceAttack
     ├── UnauthorizedAccess
     ├── SuspiciousLogin
     └── PrivilegeEscalation
```

### Strategy Pattern

Used for different security policies.

```text
SecurityPolicy
      │
 ┌────┼─────────┐
 ↓    ↓         ↓
Strict Standard Guest
```

### Observer Pattern

Used for security event notifications.

```text
ThreatDetector
      │
      ├── Logger
      ├── AlertSystem
      └── ResponseEngine
```

---

# 🖥️ VigilX Console Interface

The initial implementation is designed as a **terminal/console application**.

```text
╔══════════════════════════════════════════════╗
║                                              ║
║              🛡️ VIGILX                      ║
║       SECURITY OPERATIONS ENGINE             ║
║                                              ║
╠══════════════════════════════════════════════╣
║                                              ║
║  [1] User Management                         ║
║  [2] Resource Management                     ║
║  [3] Authentication                          ║
║  [4] Access Control                           ║
║  [5] Threat Simulator                         ║
║  [6] Threat Detection                         ║
║  [7] Incident Response                        ║
║  [8] Security Logs                            ║
║  [9] Security Statistics                      ║
║  [0] Exit                                     ║
║                                              ║
╚══════════════════════════════════════════════╝
```

---

# 🗂️ Project Structure

```text
VigilX/
│
├── include/
│   ├── User.h
│   ├── Admin.h
│   ├── Employee.h
│   ├── Guest.h
│   ├── SecurityAnalyst.h
│   │
│   ├── Resource.h
│   ├── Database.h
│   ├── Server.h
│   ├── File.h
│   ├── API.h
│   │
│   ├── Threat.h
│   ├── BruteForceAttack.h
│   ├── UnauthorizedAccess.h
│   ├── SuspiciousLogin.h
│   ├── PrivilegeEscalation.h
│   │
│   ├── SecurityPolicy.h
│   ├── ThreatDetector.h
│   ├── ResponseEngine.h
│   ├── Logger.h
│   └── SecurityEngine.h
│
├── src/
│   ├── User.cpp
│   ├── Admin.cpp
│   ├── Employee.cpp
│   ├── Guest.cpp
│   ├── SecurityAnalyst.cpp
│   │
│   ├── Resource.cpp
│   ├── Database.cpp
│   ├── Server.cpp
│   ├── File.cpp
│   ├── API.cpp
│   │
│   ├── Threat.cpp
│   ├── BruteForceAttack.cpp
│   ├── UnauthorizedAccess.cpp
│   ├── SuspiciousLogin.cpp
│   ├── PrivilegeEscalation.cpp
│   │
│   ├── SecurityPolicy.cpp
│   ├── ThreatDetector.cpp
│   ├── ResponseEngine.cpp
│   ├── Logger.cpp
│   └── SecurityEngine.cpp
│
├── data/
│   ├── users.txt
│   ├── resources.txt
│   ├── policies.txt
│   └── security_logs.txt
│
├── docs/
│   ├── class-diagram.png
│   ├── architecture.png
│   └── workflow.png
│
├── main.cpp
├── CMakeLists.txt
├── README.md
└── LICENSE
```

---

# 🛠️ Technology Stack

| Technology      | Purpose                                 |
| --------------- | --------------------------------------- |
| **C++**         | Core application and OOP implementation |
| **VS Code**     | Development environment                 |
| **g++ / MinGW** | C++ compilation                         |
| **CMake**       | Project build management                |
| **Git**         | Version control                         |
| **GitHub**      | Repository and project submission       |
| **draw.io**     | UML and architecture diagrams           |
| **GoogleTest**  | Optional automated testing              |

The initial version does **not** require a database, web frontend or external cybersecurity tools.

---

# 🧪 Testing Strategy

VigilX will be tested using different security scenarios.

### Authentication Testing

```text
✓ Correct Credentials
✓ Wrong Password
✓ Multiple Failed Attempts
✓ Locked Account
```

### Access Control Testing

```text
✓ Admin → Admin Panel
✓ Employee → Database
✓ Guest → Public File
✗ Guest → Admin Panel
✗ Employee → Admin Panel
```

### Threat Testing

```text
✓ Brute Force
✓ Unauthorized Access
✓ Suspicious Login
✓ Privilege Escalation
```

### Response Testing

```text
✓ Account Lock
✓ Access Blocking
✓ Alert Generation
✓ Incident Logging
```

---

# 🚀 Development Roadmap

### Phase 1 — Core OOP

* [x] Project architecture
* [ ] User class
* [ ] Admin / Employee / Guest
* [ ] Resource classes
* [ ] Authentication

### Phase 2 — Security

* [ ] RBAC
* [ ] Security policies
* [ ] Access validation
* [ ] Account locking

### Phase 3 — Threat Engine

* [ ] Threat base class
* [ ] Brute Force
* [ ] Unauthorized Access
* [ ] Suspicious Login
* [ ] Privilege Escalation

### Phase 4 — Detection & Response

* [ ] Threat Detector
* [ ] Severity classification
* [ ] Response Engine
* [ ] Alert generation

### Phase 5 — Persistence

* [ ] User data storage
* [ ] Resource storage
* [ ] Security policies
* [ ] Security logs

### Phase 6 — Advanced OOP

* [ ] Factory Pattern
* [ ] Strategy Pattern
* [ ] Observer Pattern
* [ ] Singleton Pattern
* [ ] Advanced exception handling
* [ ] STL optimization

### Phase 7 — Finalization

* [ ] Console dashboard
* [ ] Security statistics
* [ ] UML diagrams
* [ ] Testing
* [ ] Documentation
* [ ] GitHub presentation

---

# 🔮 Future Scope

VigilX can be expanded beyond the core C++ simulation engine.

Possible future upgrades include:

### 🌐 Web Dashboard

A graphical security operations dashboard for monitoring incidents.

### 🗄️ Database Integration

Move from text files to:

```text
MySQL / PostgreSQL / MongoDB
```

### 🔌 API Layer

Expose VigilX functionality through REST APIs.

### 🤖 AI-Based Threat Detection

Machine-learning models could analyze security events and identify abnormal behavior.

### 📈 Real-Time Security Visualization

Display:

* Threat frequency
* Severity distribution
* Attack trends
* Security score
* Incident timeline

### 🧠 Intelligent Threat Scoring

Automatically calculate threat scores based on:

```text
User Behavior
      +
Access Pattern
      +
Failed Attempts
      +
Resource Sensitivity
      ↓
Threat Score
```

### 📊 Automated Incident Reports

Generate detailed security reports for administrators and security analysts.

---

# 🔐 Security & Ethics

VigilX is strictly designed as an **educational and defensive cybersecurity simulation**.

The project:

* Does not perform real cyber attacks.
* Does not crack real passwords.
* Does not exploit real websites.
* Does not attack real networks.
* Does not collect real credentials.
* Operates entirely within a controlled simulated environment.

The objective is to understand **cybersecurity concepts, security operations and defensive system design through C++ OOP**.

---

# 🎓 Academic Relevance

VigilX demonstrates practical implementation of:

```text
Classes
Objects
Encapsulation
Inheritance
Polymorphism
Abstraction
Function Overloading
Function Overriding
Constructors
Destructors
Association
Aggregation
Composition
STL
Exception Handling
File Handling
Design Patterns
```

Instead of demonstrating these concepts individually, VigilX integrates them into a **single real-world-inspired system**.

---

# 🏆 Final Goal

The ultimate goal of **VigilX** is to build a modular C++ cybersecurity simulation engine capable of:

```text
        VIGILX
           │
           ↓
      Virtual Environment
           │
           ↓
       User Activity
           │
           ↓
      Threat Simulation
           │
           ↓
      Threat Detection
           │
           ↓
       Risk Analysis
           │
           ↓
      Incident Response
           │
           ↓
      Security Logging
           │
           ↓
      Security Analytics
```

> **VigilX — Simulate. Detect. Respond. Protect.**

---

## 👨‍💻 Project

**Project Name:** VigilX
**Category:** Cybersecurity Simulation
**Language:** C++
**Paradigm:** Object-Oriented Programming
**Application Type:** Console-Based Security Operations Engine
**Purpose:** Educational & Defensive Cybersecurity Simulation
