unit TorServerSocket;
//Some compiler directives - Please note I created these components on Delphi 12.2! and did not test them out on any other Delphi Versions!
{$IF CompilerVersion >= 21.0}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
{$ENDIF}

interface

uses
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  System.Generics.Collections,
  Winapi.Windows,
  Winapi.Winsock2,
  TorEngine;

type
  TTorServerSocket = class;
  TTorServerClient = class;

  TTorServerClientEvent = procedure(Sender: TObject; Client: TTorServerClient) of object;
  TTorServerClientDataEvent = procedure(Sender: TObject; Client: TTorServerClient;
    const Data: TBytes) of object;
  TTorServerErrorEvent = procedure(Sender: TObject; const ErrorMessage: string) of object;


  TTorServerState = (
    tssInactive,
    tssStartingTor,
    tssBootstrapping,
    tssCreatingOnion,
    tssListening
  );

  { =========================================================================
    TTorServerClient - Represents a connected client
    ========================================================================= }
  TTorServerClient = class
  private
    FSocket: TSocket;
    FID: Integer;
    FRemoteInfo: string;
    FTag: NativeInt;
    FConnectedAt: TDateTime;
  public
    constructor Create(ASocket: TSocket; AID: Integer);
    destructor Destroy; override;

    { Send data to this client }
    procedure Send(const ABuf; ALen: Integer); overload;
    procedure Send(const ABytes: TBytes); overload;
    procedure Send(const AStr: string); overload;

    { Disconnect this client }
    procedure Disconnect;

    property Socket: TSocket read FSocket;
    property ID: Integer read FID;
    property RemoteInfo: string read FRemoteInfo;
    property Tag: NativeInt read FTag write FTag;
    property ConnectedAt: TDateTime read FConnectedAt;
  end;

  { =========================================================================
    Client reader thread - one per connected client
    ========================================================================= }
  TTorClientReaderThread = class(TThread)
  private
    FOwner: TTorServerSocket;
    FClient: TTorServerClient;
  protected
    procedure Execute; override;
  public
    constructor Create(AOwner: TTorServerSocket; AClient: TTorServerClient);
  end;

  { =========================================================================
    Server accept thread - listens for incoming connections
    ========================================================================= }
  TTorServerWorker = class(TThread)
  private
    FOwner: TTorServerSocket;
    FStopEvent: TEvent;
    FTorProcess: TTorProcess;
    FListenSocket: TSocket;
    FServiceInfo: TOnionServiceInfo;
    FNextClientID: Integer;
    procedure DoSetup;
    procedure DoAcceptLoop;
    procedure FireError(const AMsg: string);
    procedure FireTorReady;
    procedure SetOwnerState(AState: TTorServerState);
  protected
    procedure Execute; override;
  public
    constructor Create(AOwner: TTorServerSocket);
    destructor Destroy; override;
    procedure SignalStop;
  end;

  { =========================================================================
    TTorServerSocket - VCL Component
    ========================================================================= }
  TTorServerSocket = class(TComponent)
  private
    { Configuration }
    FTorExePath: string;
    FDataDirectory: string;
    FSocksPort: Word;
    FControlPort: Word;
    FVirtualPort: Word;
    FLocalPort: Word;
    FPrivateKey: string;
    FActive: Boolean;
    FAutoStartTor: Boolean;

    { State }
    FState: TTorServerState;
    FOnionAddress: string;
    FWorker: TTorServerWorker;
    FClients: TObjectList<TTorServerClient>;
    FClientThreads: TObjectList<TTorClientReaderThread>;
    FShuttingDown: Boolean;
    FLock: TCriticalSection;

    { Events }
    FOnClientConnected: TTorServerClientEvent;
    FOnClientDisconnected: TTorServerClientEvent;
    FOnClientData: TTorServerClientDataEvent;
    FOnError: TTorServerErrorEvent;
    FOnTorReady: TNotifyEvent;
    FOnOnionAddress: TNotifyEvent;

    { Property setters }
    procedure SetActive(Value: Boolean);
    procedure SetVirtualPort(Value: Word);
    procedure SetLocalPort(Value: Word);
    procedure SetTorExePath(const Value: string);

    { Internal }
    procedure DoStart;
    procedure DoStop;
    procedure AddClient(AClient: TTorServerClient);
    function DetachClient(AClient: TTorServerClient): Boolean;
    procedure RemoveClient(AClient: TTorServerClient);
    procedure RemoveClientThread(AThread: TTorClientReaderThread);

  protected
    procedure Loaded; override;

  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    { Start listening }
    procedure Start;

    { Stop listening and disconnect all clients }
    procedure Stop;

    { Send data to all connected clients }
    procedure Broadcast(const ABuf; ALen: Integer); overload;
    procedure Broadcast(const ABytes: TBytes); overload;
    procedure Broadcast(const AStr: string); overload;

    { Send data to a specific client by ID }
    procedure SendToClient(AClientID: Integer; const ABytes: TBytes);

    { Disconnect a specific client }
    procedure DisconnectClient(AClientID: Integer);

    { Get number of connected clients }
    function ClientCount: Integer;

    { The .onion address (available after OnTorReady) }
    property OnionAddress: string read FOnionAddress;

    { Current state }
    property State: TTorServerState read FState;

    { Private key for reuse (save this to keep same .onion address) }
    property PrivateKeyBlob: string read FPrivateKey;

  published
    { Path to tor.exe }
    property TorExePath: string read FTorExePath write SetTorExePath;

    { Directory for TOR data/cache }
    property DataDirectory: string read FDataDirectory write FDataDirectory;

    { TOR SOCKS5 proxy port (default 9050) }
    property SocksPort: Word read FSocksPort write FSocksPort default 9050;

    { TOR control port (default 9051) }
    property ControlPort: Word read FControlPort write FControlPort default 9051;

    { Port visible on the .onion address (what clients connect to) }
    property VirtualPort: Word read FVirtualPort write SetVirtualPort default 80;

    { Local port to listen on (TOR maps VirtualPort -> LocalPort) }
    property LocalPort: Word read FLocalPort write SetLocalPort default 8080;

    { Provide a previously saved private key to keep the same .onion address.
      Format: 'ED25519-V3:<base64>' }
    property PrivateKey: string read FPrivateKey write FPrivateKey;

    { Activate/deactivate }
    property Active: Boolean read FActive write SetActive default False;

    { Auto-start tor.exe (default True) }
    property AutoStartTor: Boolean read FAutoStartTor write FAutoStartTor default True;

    { Events }
    property OnClientConnected: TTorServerClientEvent read FOnClientConnected write FOnClientConnected;
    property OnClientDisconnected: TTorServerClientEvent read FOnClientDisconnected write FOnClientDisconnected;
    property OnClientData: TTorServerClientDataEvent read FOnClientData write FOnClientData;
    property OnError: TTorServerErrorEvent read FOnError write FOnError;
    property OnTorReady: TNotifyEvent read FOnTorReady write FOnTorReady;
    property OnOnionAddress: TNotifyEvent read FOnOnionAddress write FOnOnionAddress;
  end;

implementation

{ =========================================================================
  TTorServerClient
  ========================================================================= }

constructor TTorServerClient.Create(ASocket: TSocket; AID: Integer);
begin
  inherited Create;
  FSocket := ASocket;
  FID := AID;
  FTag := 0;
  FConnectedAt := Now;
  FRemoteInfo := Format('TorClient_%d', [AID]);
end;

destructor TTorServerClient.Destroy;
begin
  Disconnect;
  inherited;
end;

procedure TTorServerClient.Send(const ABuf; ALen: Integer);
begin
  if FSocket <> INVALID_SOCKET then
    SendAll(FSocket, ABuf, ALen);
end;

procedure TTorServerClient.Send(const ABytes: TBytes);
begin
  if Length(ABytes) > 0 then
    Send(ABytes[0], Length(ABytes));
end;

procedure TTorServerClient.Send(const AStr: string);
var
  Buf: TBytes;
begin
  Buf := TEncoding.UTF8.GetBytes(AStr);
  Send(Buf);
end;

procedure TTorServerClient.Disconnect;
begin
  SafeCloseSocket(FSocket);
end;

{ =========================================================================
  TTorClientReaderThread
  ========================================================================= }

constructor TTorClientReaderThread.Create(AOwner: TTorServerSocket; AClient: TTorServerClient);
begin
  inherited Create(False); { Start immediately }
  FreeOnTerminate := False;
  FOwner := AOwner;
  FClient := AClient;
end;

procedure TTorClientReaderThread.Execute;
var
  Buf: TBytes;
  Recvd: Integer;
  DataCopy: TBytes;
  OwnerRef: TTorServerSocket;
  ThreadRef: TTorClientReaderThread;
  ClientRef: TTorServerClient;
begin
  OwnerRef := FOwner;
  ThreadRef := Self;
  ClientRef := FClient;
  try
    SetLength(Buf, 65536);
    while not Terminated do
    begin
      if ClientRef.Socket = INVALID_SOCKET then
        Break;

      Recvd := recv(ClientRef.Socket, Buf[0], Length(Buf), 0);
      if Recvd <= 0 then
        Break;

      DataCopy := Copy(Buf, 0, Recvd);
      TThread.Queue(nil,
        procedure
        begin
          if OwnerRef.FShuttingDown then
            Exit;
          if Assigned(OwnerRef.FOnClientData) then
            OwnerRef.FOnClientData(OwnerRef, ClientRef, DataCopy);
        end);
    end;
  except
    { Swallow - disconnection will be reported below }
  end;

  { Client disconnected }
  TThread.Queue(nil,
    procedure
    begin
      var Removed := False;
      if OwnerRef.FShuttingDown then
        Exit;

      { Remove from active list first so ClientCount reflects the disconnect
        inside OnClientDisconnected handlers. }
      Removed := OwnerRef.DetachClient(ClientRef);
      if Removed then
      begin
        if Assigned(OwnerRef.FOnClientDisconnected) then
          OwnerRef.FOnClientDisconnected(OwnerRef, ClientRef);
        ClientRef.Free;
      end;

      OwnerRef.RemoveClientThread(ThreadRef);
    end);
end;

{ =========================================================================
  TTorServerWorker
  ========================================================================= }

constructor TTorServerWorker.Create(AOwner: TTorServerSocket);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FOwner := AOwner;
  FStopEvent := TEvent.Create(nil, True, False, '');
  FTorProcess := nil;
  FListenSocket := INVALID_SOCKET;
  FNextClientID := 1;
end;

destructor TTorServerWorker.Destroy;
begin
  if FListenSocket <> INVALID_SOCKET then
    SafeCloseSocket(FListenSocket);
  if FTorProcess <> nil then
  begin
    FTorProcess.Stop;
    FreeAndNil(FTorProcess);
  end;
  FreeAndNil(FStopEvent);
  inherited;
end;

procedure TTorServerWorker.SignalStop;
begin
  FStopEvent.SetEvent;
  Terminate;
  { Close listen socket to unblock accept() }
  if FListenSocket <> INVALID_SOCKET then
    SafeCloseSocket(FListenSocket);
end;

procedure TTorServerWorker.SetOwnerState(AState: TTorServerState);
begin
  FOwner.FLock.Enter;
  try
    FOwner.FState := AState;
  finally
    FOwner.FLock.Leave;
  end;
end;

procedure TTorServerWorker.FireError(const AMsg: string);
begin
  if Assigned(FOwner.FOnError) then
    FOwner.FOnError(FOwner, AMsg);
end;

procedure TTorServerWorker.FireTorReady;
begin
  if Assigned(FOwner.FOnTorReady) then
    FOwner.FOnTorReady(FOwner);
end;

procedure TTorServerWorker.DoSetup;
var
  Control: TTorControlClient;
  CookiePath: string;
  Addr: TSockAddrIn;
  OptVal: Integer;
  OwnerRef: TTorServerSocket;
begin
  OwnerRef := FOwner;
  EnsureWinSockInit;

  { Step 1: Start TOR if needed }
  if OwnerRef.FAutoStartTor then
  begin
    SetOwnerState(tssStartingTor);

    FTorProcess := TTorProcess.Create;
    FTorProcess.TorExePath := OwnerRef.FTorExePath;
    FTorProcess.DataDirectory := OwnerRef.FDataDirectory;
    FTorProcess.SocksPort := OwnerRef.FSocksPort;
    FTorProcess.ControlPort := OwnerRef.FControlPort;
    FTorProcess.Start;

    Sleep(2000);

    if FStopEvent.WaitFor(0) = wrSignaled then Exit;

    { Step 2: Wait for bootstrap }
    SetOwnerState(tssBootstrapping);

    Control := TTorControlClient.Create(OwnerRef.FControlPort);
    try
      var Retries := 0;
      var Connected := False;
      while (Retries < 30) and (not Connected) do
      begin
        if FStopEvent.WaitFor(0) = wrSignaled then Exit;
        try
          Control.Connect;
          Connected := True;
        except
          Inc(Retries);
          Sleep(1000);
        end;
      end;

      if not Connected then
        raise Exception.Create('Could not connect to TOR control port');

      CookiePath := IncludeTrailingPathDelimiter(FTorProcess.DataDirectory) + 'control_auth_cookie';

      var AuthRetries := 0;
      var Authenticated := False;
      while (AuthRetries < 10) and (not Authenticated) do
      begin
        if FStopEvent.WaitFor(0) = wrSignaled then Exit;
        try
          Authenticated := Control.AuthenticateAuto(CookiePath);
        except
        end;
        if not Authenticated then
        begin
          Inc(AuthRetries);
          Sleep(1000);
        end;
      end;

      if not Authenticated then
        raise Exception.Create('Could not authenticate with TOR control port');

      { Wait for bootstrap }
      var StartTick := GetTickCount64;
      while True do
      begin
        if FStopEvent.WaitFor(0) = wrSignaled then Exit;
        var Progress := Control.GetBootstrapProgress;
        if Progress >= 100 then
          Break;
        if (GetTickCount64 - StartTick) > 120000 then
          raise Exception.Create('TOR bootstrap timed out');
        Sleep(1000);
      end;

      TThread.Queue(nil,
        procedure
        begin
          if Assigned(OwnerRef.FOnTorReady) then
            OwnerRef.FOnTorReady(OwnerRef);
        end);

      if FStopEvent.WaitFor(0) = wrSignaled then Exit;

      { Step 3: Create local TCP listener }
      FListenSocket := Winapi.Winsock2.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      if FListenSocket = INVALID_SOCKET then
        raise Exception.CreateFmt('socket() failed: %d', [WSAGetLastError]);

      OptVal := 1;
      setsockopt(FListenSocket, SOL_SOCKET, SO_REUSEADDR, @OptVal, SizeOf(OptVal));

      FillChar(Addr, SizeOf(Addr), 0);
      Addr.sin_family := AF_INET;
      Addr.sin_port := htons(OwnerRef.FLocalPort);
      Addr.sin_addr.S_addr := inet_addr('127.0.0.1');

      if bind(FListenSocket, TSockAddr(Addr), SizeOf(Addr)) = SOCKET_ERROR then
        raise Exception.CreateFmt('bind() to port %d failed: %d',
          [OwnerRef.FLocalPort, WSAGetLastError]);

      if listen(FListenSocket, SOMAXCONN) = SOCKET_ERROR then
        raise Exception.CreateFmt('listen() failed: %d', [WSAGetLastError]);

      { Step 4: Create the hidden service via ADD_ONION }
      SetOwnerState(tssCreatingOnion);

      FServiceInfo := Control.AddOnion(OwnerRef.FVirtualPort, OwnerRef.FLocalPort,
        OwnerRef.FPrivateKey);

      { Store the results }
      OwnerRef.FLock.Enter;
      try
        OwnerRef.FOnionAddress := FServiceInfo.OnionAddress;
        if FServiceInfo.PrivateKey <> '' then
          OwnerRef.FPrivateKey := FServiceInfo.PrivateKey;
      finally
        OwnerRef.FLock.Leave;
      end;

      { Fire OnOnionAddress on main thread }
      TThread.Queue(nil,
        procedure
        begin
          if Assigned(OwnerRef.FOnOnionAddress) then
            OwnerRef.FOnOnionAddress(OwnerRef);
        end);
    finally
      Control.Free;
    end;
  end
  else
  begin
    { Not auto-starting TOR - just bind locally }
    FListenSocket := Winapi.Winsock2.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if FListenSocket = INVALID_SOCKET then
      raise Exception.CreateFmt('socket() failed: %d', [WSAGetLastError]);

    OptVal := 1;
    setsockopt(FListenSocket, SOL_SOCKET, SO_REUSEADDR, @OptVal, SizeOf(OptVal));

    FillChar(Addr, SizeOf(Addr), 0);
    Addr.sin_family := AF_INET;
    Addr.sin_port := htons(OwnerRef.FLocalPort);
    Addr.sin_addr.S_addr := inet_addr('127.0.0.1');

    if bind(FListenSocket, TSockAddr(Addr), SizeOf(Addr)) = SOCKET_ERROR then
      raise Exception.CreateFmt('bind() to port %d failed: %d',
        [OwnerRef.FLocalPort, WSAGetLastError]);

    if listen(FListenSocket, SOMAXCONN) = SOCKET_ERROR then
      raise Exception.CreateFmt('listen() failed: %d', [WSAGetLastError]);
  end;

  SetOwnerState(tssListening);
end;

procedure TTorServerWorker.DoAcceptLoop;
var
  ClientSock: TSocket;
  ClientAddr: TSockAddrIn;
  AddrLen: Integer;
  Client: TTorServerClient;
  ReaderThread: TTorClientReaderThread;
  OwnerRef: TTorServerSocket;
begin
  OwnerRef := FOwner;

  while not Terminated do
  begin
    if FStopEvent.WaitFor(0) = wrSignaled then
      Break;

    AddrLen := SizeOf(ClientAddr);
    ClientSock := accept(FListenSocket, @ClientAddr, @AddrLen);

    if ClientSock = INVALID_SOCKET then
    begin
      if Terminated then
        Break;
      Continue;
    end;

    { Create client wrapper }
    Client := TTorServerClient.Create(ClientSock, FNextClientID);
    Inc(FNextClientID);

    { Add to owner's client list }
    OwnerRef.AddClient(Client);

    { Fire OnClientConnected }
    TThread.Queue(nil,
      procedure
      begin
        if OwnerRef.FShuttingDown then
          Exit;
        if Assigned(OwnerRef.FOnClientConnected) then
          OwnerRef.FOnClientConnected(OwnerRef, Client);
      end);

    { Start a reader thread for this client }
    ReaderThread := TTorClientReaderThread.Create(OwnerRef, Client);
    OwnerRef.FLock.Enter;
    try
      OwnerRef.FClientThreads.Add(ReaderThread);
    finally
      OwnerRef.FLock.Leave;
    end;
  end;
end;

procedure TTorServerWorker.Execute;
var
  OwnerRef: TTorServerSocket;
begin
  OwnerRef := FOwner;

  try
    DoSetup;
    if not Terminated then
      DoAcceptLoop;
  except
    on E: Exception do
    begin
      var Msg := E.Message;
      TThread.Queue(nil,
        procedure
        begin
          if Assigned(OwnerRef.FOnError) then
            OwnerRef.FOnError(OwnerRef, Msg);
        end);
    end;
  end;

  SetOwnerState(tssInactive);
end;

{ =========================================================================
  TTorServerSocket
  ========================================================================= }

constructor TTorServerSocket.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FLock := TCriticalSection.Create;
  FClients := TObjectList<TTorServerClient>.Create(False); { We manage lifetime manually }
  FClientThreads := TObjectList<TTorClientReaderThread>.Create(False); { Managed manually }
  FState := tssInactive;
  FActive := False;
  FAutoStartTor := True;
  FSocksPort := TOR_DEFAULT_SOCKS_PORT;
  FControlPort := TOR_DEFAULT_CONTROL_PORT;
  FVirtualPort := 80;
  FLocalPort := 8080;
  FWorker := nil;
  FShuttingDown := False;
  FOnionAddress := '';
end;

destructor TTorServerSocket.Destroy;
var
  I: Integer;
begin
  DoStop;
  FreeAndNil(FClientThreads);
  { Free any remaining client objects since FClients doesn't own them }
  if FClients <> nil then
  begin
    for I := 0 to FClients.Count - 1 do
      FClients[I].Free;
    FreeAndNil(FClients);
  end;
  FreeAndNil(FLock);
  inherited;
end;

procedure TTorServerSocket.Loaded;
begin
  inherited;
  if FActive and not (csDesigning in ComponentState) then
    DoStart;
end;

procedure TTorServerSocket.SetActive(Value: Boolean);
begin
  if FActive = Value then Exit;

  if csDesigning in ComponentState then
  begin
    FActive := Value;
    Exit;
  end;

  if csLoading in ComponentState then
  begin
    FActive := Value;
    Exit;
  end;

  if Value then
    DoStart
  else
    DoStop;
end;

procedure TTorServerSocket.SetVirtualPort(Value: Word);
begin
  if FActive and not (csDesigning in ComponentState) then
    raise Exception.Create('Cannot change VirtualPort while Active');
  FVirtualPort := Value;
end;

procedure TTorServerSocket.SetLocalPort(Value: Word);
begin
  if FActive and not (csDesigning in ComponentState) then
    raise Exception.Create('Cannot change LocalPort while Active');
  FLocalPort := Value;
end;

procedure TTorServerSocket.SetTorExePath(const Value: string);
begin
  if FActive and not (csDesigning in ComponentState) then
    raise Exception.Create('Cannot change TorExePath while Active');
  FTorExePath := Value;
end;

procedure TTorServerSocket.DoStart;
begin
  if FWorker <> nil then
    Exit;

  FShuttingDown := False;
  FActive := True;
  FState := tssStartingTor;
  FOnionAddress := '';

  FWorker := TTorServerWorker.Create(Self);
  FWorker.Start;
end;

procedure TTorServerSocket.DoStop;
var
  I: Integer;
  ClientsCopy: TList<TTorServerClient>;
  ThreadsCopy: TList<TTorClientReaderThread>;
  FlushUntil: UInt64;
begin
  FShuttingDown := True;

  { Signal worker to stop (closes listen socket to unblock accept) }
  if FWorker <> nil then
  begin
    FWorker.SignalStop;
    FWorker.WaitFor;
    FreeAndNil(FWorker);
  end;

  { Snapshot clients and reader threads under lock }
  ClientsCopy := TList<TTorServerClient>.Create;
  ThreadsCopy := TList<TTorClientReaderThread>.Create;
  try
    FLock.Enter;
    try
      for I := 0 to FClients.Count - 1 do
        ClientsCopy.Add(FClients[I]);
      for I := 0 to FClientThreads.Count - 1 do
        ThreadsCopy.Add(FClientThreads[I]);
    finally
      FLock.Leave;
    end;

    { Disconnect clients first so recv() unblocks in reader threads }
    for I := 0 to ClientsCopy.Count - 1 do
      ClientsCopy[I].Disconnect;

    { Wait for all reader threads to exit cleanly }
    for I := 0 to ThreadsCopy.Count - 1 do
    begin
      ThreadsCopy[I].Terminate;
      ThreadsCopy[I].WaitFor;
    end;

    { Remove references from internal lists }
    FLock.Enter;
    try
      FClients.Clear;
      FClientThreads.Clear;
    finally
      FLock.Leave;
    end;

    { Now safe to free client wrappers and reader thread objects }
    for I := 0 to ClientsCopy.Count - 1 do
      ClientsCopy[I].Free;
    for I := 0 to ThreadsCopy.Count - 1 do
      ThreadsCopy[I].Free;
  finally
    ThreadsCopy.Free;
    ClientsCopy.Free;
  end;

  if GetCurrentThreadID = MainThreadID then
  begin
    FlushUntil := GetTickCount64 + 250;
    repeat
      CheckSynchronize(10);
    until GetTickCount64 >= FlushUntil;
  end;

  FActive := False;
  FState := tssInactive;
  FOnionAddress := '';
end;

procedure TTorServerSocket.Start;
begin
  SetActive(True);
end;

procedure TTorServerSocket.Stop;
begin
  SetActive(False);
end;

procedure TTorServerSocket.AddClient(AClient: TTorServerClient);
begin
  FLock.Enter;
  try
    FClients.Add(AClient);
  finally
    FLock.Leave;
  end;
end;

function TTorServerSocket.DetachClient(AClient: TTorServerClient): Boolean;
begin
  Result := False;
  FLock.Enter;
  try
    Result := FClients.Remove(AClient) >= 0;
  finally
    FLock.Leave;
  end;
end;

procedure TTorServerSocket.RemoveClient(AClient: TTorServerClient);
begin
  { Only free if we actually owned it; if DoStop already cleared the list
    and freed the client, skip to avoid double-free }
  if DetachClient(AClient) then
    AClient.Free;
end;

procedure TTorServerSocket.RemoveClientThread(AThread: TTorClientReaderThread);
var
  Found: Boolean;
begin
  Found := False;
  FLock.Enter;
  try
    if FClientThreads.IndexOf(AThread) >= 0 then
    begin
      FClientThreads.Remove(AThread);
      Found := True;
    end;
  finally
    FLock.Leave;
  end;

  if Found then
    AThread.Free;
end;

procedure TTorServerSocket.Broadcast(const ABuf; ALen: Integer);
var
  I: Integer;
begin
  FLock.Enter;
  try
    for I := 0 to FClients.Count - 1 do
    begin
      try
        FClients[I].Send(ABuf, ALen);
      except
        { Skip clients that errored }
      end;
    end;
  finally
    FLock.Leave;
  end;
end;

procedure TTorServerSocket.Broadcast(const ABytes: TBytes);
begin
  if Length(ABytes) > 0 then
    Broadcast(ABytes[0], Length(ABytes));
end;

procedure TTorServerSocket.Broadcast(const AStr: string);
var
  Buf: TBytes;
begin
  Buf := TEncoding.UTF8.GetBytes(AStr);
  Broadcast(Buf);
end;

procedure TTorServerSocket.SendToClient(AClientID: Integer; const ABytes: TBytes);
var
  I: Integer;
begin
  FLock.Enter;
  try
    for I := 0 to FClients.Count - 1 do
    begin
      if FClients[I].ID = AClientID then
      begin
        FClients[I].Send(ABytes);
        Break;
      end;
    end;
  finally
    FLock.Leave;
  end;
end;

procedure TTorServerSocket.DisconnectClient(AClientID: Integer);
var
  I: Integer;
begin
  FLock.Enter;
  try
    for I := 0 to FClients.Count - 1 do
    begin
      if FClients[I].ID = AClientID then
      begin
        FClients[I].Disconnect;
        Break;
      end;
    end;
  finally
    FLock.Leave;
  end;
end;

function TTorServerSocket.ClientCount: Integer;
begin
  FLock.Enter;
  try
    Result := FClients.Count;
  finally
    FLock.Leave;
  end;
end;

end.
