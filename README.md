# 🧅 TOR Socket Components for Delphi

### Professional Native TOR Client & Server Components

![Delphi](https://img.shields.io/badge/Delphi-12.2+-red?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20Win32%20%7C%20Win64-blue?style=for-the-badge)
![Dependencies](https://img.shields.io/badge/Dependency-TOR.exe-success?style=for-the-badge)
![Network](https://img.shields.io/badge/Network-TOR%20Onion%20Services-purple?style=for-the-badge)

------------------------------------------------------------------------
<p align="center">
  <img src="https://raw.githubusercontent.com/BitmasterXor/Delphi_TOR_SOCKETS/main/TORComponents.png" alt="TOR Components">
</p>
# 🚀 Overview

TOR Socket Components for Delphi is a fully native, zero‑dependency TOR
networking component suite written entirely in Delphi.

It allows your applications to:

• Connect to TOR hidden services (.onion)\
• Host TOR hidden services\
• Build anonymous servers and clients\
• Run TOR networking without external libraries, Only the initial TOR.exe binary is required!

No OpenSSL.\
No external DLL dependencies.

Only tor.exe is required.

------------------------------------------------------------------------

# ✨ Features

## Native TOR Engine

• Fully written in Delphi\
• Automatic tor.exe management\
• SOCKS5 protocol implementation\
• TOR Control Protocol support\
• Bootstrap monitoring\
• Hidden service creation (for the TOR.exe Binary)

------------------------------------------------------------------------

## TTorClientSocket

Connect to hidden services easily.

Capabilities:

• Connect to .onion addresses\
• Fully asynchronous\
• Threaded networking\
• Event‑driven architecture\
• Automatic TOR startup

Events:

OnConnected\
OnDisconnected\
OnDataReceived\
OnError

------------------------------------------------------------------------

## TTorServerSocket

Host your own TOR hidden service.

Capabilities:

• Automatic onion service creation\
• Accept anonymous clients\
• Multi‑client support\
• Fully threaded\
• Send and receive data

------------------------------------------------------------------------

# 📦 Package Contents

TorEngine.pas --- Core TOR engine\
TorClientSocket.pas --- Client component\
TorServerSocket.pas --- Server component\
TorSocketReg.pas --- Component registration\
TorSocketComponents.dpk --- Delphi package

------------------------------------------------------------------------

# 🛠 Installation

Step 1

Open in Delphi:

TorSocketComponents.dpk

Build & Install

Components appear in Component Palette → TOR Sockets

------------------------------------------------------------------------

Step 2

Download TOR Expert Bundle:

https://www.torproject.org/download/tor/

Place tor.exe in your application folder. (or use whatever method you wish Ex: Exe resources ect... ect...)

------------------------------------------------------------------------

# ⚡ Client Example

``` pascal
TorClient := TTorClientSocket.Create(Self);
TorClient.TorExePath := 'tor.exe';
TorClient.DataDirectory := 'tor_data';
TorClient.OnionAddress := 'example.onion';
TorClient.OnionPort := 80;
TorClient.Active := True;
```

------------------------------------------------------------------------

# 🧅 Server Example

``` pascal
TorServer := TTorServerSocket.Create(Self);
TorServer.TorExePath := 'tor.exe';
TorServer.DataDirectory := 'tor_service';
TorServer.Active := True;
```

------------------------------------------------------------------------

# ⚙ Requirements

Delphi 12+\
Windows 10/11\
tor.exe

------------------------------------------------------------------------

# 🛡 Security

Provides full TOR anonymity.

Your real IP address is never exposed.

------------------------------------------------------------------------

# 🧑‍💻 Author

BitmasterXor

Malware Researcher\
Delphi Developer

GitHub\
https://github.com/BitmasterXor

------------------------------------------------------------------------

# ⭐ Support

Star the project if you find it useful.
