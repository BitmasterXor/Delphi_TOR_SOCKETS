unit TorClientSocket;
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
  Winapi.Windows,
  Winapi.Winsock2,
  TorEngine;

type
  { Event types }
  TTorDataEvent = procedure(Sender: TObject; const Data: TBytes) of object;
  TTorErrorEvent = procedure(Sender: TObject; const ErrorMessage: string) of object;

  { Connection state }
  TTorClientState = (
    tcsDisconnected,
    tcsStartingTor,
    tcsBootstrapping,
    tcsConnecting,
    tcsConnected
  );

  { Forward declaration }
  TTorClientSocket = class;

  { Worker thread - manages TOR process, connects, and reads data }
  TTorClientWorker = class(TThread)
  private
    FOwner: TTorClientSocket;
    FStopEvent: TEvent;
    FTorProcess: TTorProcess;
    FSocks5: TSocks5Client;
    FMonitorControl: TTorControlClient;
    procedure DoConnect;
    procedure DoReadLoop;
    procedure FireConnected;
    procedure FireDisconnected;
    procedure FireData(const AData: TBytes);
    procedure FireError(const AMsg: string);
    procedure FireTorReady;
    procedure SetOwnerState(AState: TTorClientState);
  protected
    procedure Execute; override;
  public
    constructor Create(AOwner: TTorClientSocket);
    destructor Destroy; override;
    procedure SignalStop;
    property Socks5: TSocks5Client read FSocks5;
  end;

  { =========================================================================
    TTorClientSocket - VCL Component
    ========================================================================= }
  TTorClientSocket = class(TComponent)
  private
    { Configuration }
    FTorExePath: string;
    FDataDirectory: string;
    FSocksPort: Word;
    FControlPort: Word;
    FOnionAddress: string;
    FOnionPort: Word;
    FActive: Boolean;
    FAutoStartTor: Boolean;

    { State }
    FState: TTorClientState;
    FWorker: TTorClientWorker;
    FLock: TCriticalSection;

    { Events }
    FOnConnected: TNotifyEvent;
    FOnDisconnected: TNotifyEvent;
    FOnDataReceived: TTorDataEvent;
    FOnError: TTorErrorEvent;
    FOnTorReady: TNotifyEvent;

    { Property setters }
    procedure SetActive(Value: Boolean);
    procedure SetOnionAddress(const Value: string);
    procedure SetOnionPort(Value: Word);
    procedure SetTorExePath(const Value: string);
    procedure SetSocksPort(Value: Word);
    procedure SetControlPort(Value: Word);

    { Internal }
    procedure DoStart;
    procedure DoStop;

  protected
    procedure Loaded; override;

  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    { Connect to the .onion address }
    procedure Connect;

    { Disconnect }
    procedure Disconnect;

    { Send data over the tunnel }
    procedure Send(const ABuf; ALen: Integer); overload;
    procedure Send(const ABytes: TBytes); overload;
    procedure Send(const AStr: string); overload;

    { Request a new TOR circuit (new identity) }
    procedure NewIdentity;

    { Current state }
    property State: TTorClientState read FState;

  published
    { Path to tor.exe - searches app directory if empty }
    property TorExePath: string read FTorExePath write SetTorExePath;

    { Directory for TOR data/cache files }
    property DataDirectory: string read FDataDirectory write FDataDirectory;

    { TOR SOCKS5 proxy port (default 9050) }
    property SocksPort: Word read FSocksPort write SetSocksPort default 9050;

    { TOR control port (default 9051) }
    property ControlPort: Word read FControlPort write SetControlPort default 9051;

    { The .onion address to connect to }
    property OnionAddress: string read FOnionAddress write SetOnionAddress;

    { Port on the .onion hidden service }
    property OnionPort: Word read FOnionPort write SetOnionPort default 80;

    { Activate/deactivate the connection }
    property Active: Boolean read FActive write SetActive default False;

    { Auto-start tor.exe if not already running (default True) }
    property AutoStartTor: Boolean read FAutoStartTor write FAutoStartTor default True;

    { Events }
    property OnConnected: TNotifyEvent read FOnConnected write FOnConnected;
    property OnDisconnected: TNotifyEvent read FOnDisconnected write FOnDisconnected;
    property OnDataReceived: TTorDataEvent read FOnDataReceived write FOnDataReceived;
    property OnError: TTorErrorEvent read FOnError write FOnError;
    property OnTorReady: TNotifyEvent read FOnTorReady write FOnTorReady;
  end;

implementation

{ =========================================================================
  TTorClientWorker
  ========================================================================= }

constructor TTorClientWorker.Create(AOwner: TTorClientSocket);
begin
  inherited Create(True); { Create suspended }
  FreeOnTerminate := False;
  FOwner := AOwner;
  FStopEvent := TEvent.Create(nil, True, False, '');
  FTorProcess := nil;
  FSocks5 := nil;
  FMonitorControl := nil;
end;

destructor TTorClientWorker.Destroy;
begin
  if FSocks5 <> nil then
  begin
    FSocks5.Disconnect;
    FreeAndNil(FSocks5);
  end;
  if FMonitorControl <> nil then
  begin
    FMonitorControl.Disconnect;
    FreeAndNil(FMonitorControl);
  end;
  if FTorProcess <> nil then
  begin
    FTorProcess.Stop;
    FreeAndNil(FTorProcess);
  end;
  FreeAndNil(FStopEvent);
  inherited;
end;

procedure TTorClientWorker.SignalStop;
begin
  FStopEvent.SetEvent;
  Terminate;
end;

procedure TTorClientWorker.SetOwnerState(AState: TTorClientState);
begin
  FOwner.FLock.Enter;
  try
    FOwner.FState := AState;
  finally
    FOwner.FLock.Leave;
  end;
end;

procedure TTorClientWorker.FireConnected;
begin
  if Assigned(FOwner.FOnConnected) then
    FOwner.FOnConnected(FOwner);
end;

procedure TTorClientWorker.FireDisconnected;
begin
  if Assigned(FOwner.FOnDisconnected) then
    FOwner.FOnDisconnected(FOwner);
end;

procedure TTorClientWorker.FireData(const AData: TBytes);
begin
  if Assigned(FOwner.FOnDataReceived) then
    FOwner.FOnDataReceived(FOwner, AData);
end;

procedure TTorClientWorker.FireError(const AMsg: string);
begin
  if Assigned(FOwner.FOnError) then
    FOwner.FOnError(FOwner, AMsg);
end;

procedure TTorClientWorker.FireTorReady;
begin
  if Assigned(FOwner.FOnTorReady) then
    FOwner.FOnTorReady(FOwner);
end;

procedure TTorClientWorker.DoConnect;
var
  Control: TTorControlClient;
  CookiePath: string;
  OwnerRef: TTorClientSocket;
  MonitorCookiePath: string;
begin
  OwnerRef := FOwner;

  { Step 1: Start TOR if needed }
  if OwnerRef.FAutoStartTor then
  begin
    SetOwnerState(tcsStartingTor);

    FTorProcess := TTorProcess.Create;
    FTorProcess.TorExePath := OwnerRef.FTorExePath;
    FTorProcess.DataDirectory := OwnerRef.FDataDirectory;
    FTorProcess.SocksPort := OwnerRef.FSocksPort;
    FTorProcess.ControlPort := OwnerRef.FControlPort;
    FTorProcess.Start;

    { Wait a moment for TOR to open its control port }
    Sleep(2000);

    if FStopEvent.WaitFor(0) = wrSignaled then Exit;

    { Step 2: Wait for TOR to bootstrap }
    SetOwnerState(tcsBootstrapping);

    Control := TTorControlClient.Create(OwnerRef.FControlPort);
    try
      { Retry connecting to control port (TOR might still be starting) }
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

      { Authenticate with cookie }
      CookiePath := IncludeTrailingPathDelimiter(FTorProcess.DataDirectory) + 'control_auth_cookie';

      var AuthRetries := 0;
      var Authenticated := False;
      while (AuthRetries < 10) and (not Authenticated) do
      begin
        if FStopEvent.WaitFor(0) = wrSignaled then Exit;
        try
          Authenticated := Control.AuthenticateAuto(CookiePath);
        except
          { Cookie file might not be written yet }
        end;
        if not Authenticated then
        begin
          Inc(AuthRetries);
          Sleep(1000);
        end;
      end;

      if not Authenticated then
        raise Exception.Create('Could not authenticate with TOR control port');

      { Wait for bootstrap to complete }
      var StartTick := GetTickCount64;
      while True do
      begin
        if FStopEvent.WaitFor(0) = wrSignaled then Exit;
        var Progress := Control.GetBootstrapProgress;
        if Progress >= 100 then
          Break;
        if (GetTickCount64 - StartTick) > 120000 then
          raise Exception.Create('TOR bootstrap timed out (120 seconds)');
        Sleep(1000);
      end;
    finally
      Control.Free;
    end;

    TThread.Queue(nil,
      procedure
      begin
        if Assigned(OwnerRef.FOnTorReady) then
          OwnerRef.FOnTorReady(OwnerRef);
      end);
  end;

  if FStopEvent.WaitFor(0) = wrSignaled then Exit;

  { Step 3: Connect through SOCKS5 to the .onion address }
  SetOwnerState(tcsConnecting);

  FSocks5 := TSocks5Client.Create(OwnerRef.FSocksPort);
  var ConnectStartTick := GetTickCount64;
  const ConnectTimeoutMs: UInt64 = 90000;
  while True do
  begin
    if FStopEvent.WaitFor(0) = wrSignaled then
      Exit;

    try
      FSocks5.Connect(OwnerRef.FOnionAddress, OwnerRef.FOnionPort);
      Break;
    except
      on E: Exception do
      begin
        var RetryableHSFailure :=
          (FSocks5.LastReplyCode = SOCKS5_REP_HOST_UNREACHABLE) or
          (FSocks5.LastReplyCode = SOCKS5_REP_HS_DESC_NOT_FOUND) or
          (FSocks5.LastReplyCode = SOCKS5_REP_HS_INTRO_FAILED) or
          (FSocks5.LastReplyCode = SOCKS5_REP_HS_REND_FAILED) or
          (FSocks5.LastReplyCode = SOCKS5_REP_HS_INTRO_TIMEOUT);

        if not RetryableHSFailure then
          raise;

        if (GetTickCount64 - ConnectStartTick) >= ConnectTimeoutMs then
          raise Exception.CreateFmt(
            'Timed out waiting for onion service to become reachable (%d ms). Last error: %s',
            [ConnectTimeoutMs, E.Message]);

        Sleep(2000);
      end;
    end;
  end;

  { Optional monitor control connection for idle disconnect detection. }
  MonitorCookiePath := '';
  if FTorProcess <> nil then
    MonitorCookiePath := IncludeTrailingPathDelimiter(FTorProcess.DataDirectory) + 'control_auth_cookie'
  else if OwnerRef.FDataDirectory <> '' then
    MonitorCookiePath := IncludeTrailingPathDelimiter(OwnerRef.FDataDirectory) + 'control_auth_cookie';

  FreeAndNil(FMonitorControl);
  try
    FMonitorControl := TTorControlClient.Create(OwnerRef.FControlPort);
    FMonitorControl.Connect;
    if not FMonitorControl.AuthenticateAuto(MonitorCookiePath) then
      FreeAndNil(FMonitorControl);
  except
    FreeAndNil(FMonitorControl);
  end;

  SetOwnerState(tcsConnected);
  TThread.Queue(nil,
    procedure
    begin
      if Assigned(OwnerRef.FOnConnected) then
        OwnerRef.FOnConnected(OwnerRef);
    end);
end;

procedure TTorClientWorker.DoReadLoop;
var
  Data: TBytes;
  DataCopy: TBytes;
  OwnerRef: TTorClientSocket;
  LastStreamProbeTick: UInt64;
  StreamAlive: Boolean;
begin
  OwnerRef := FOwner;
  LastStreamProbeTick := 0;

  while not Terminated do
  begin
    if FStopEvent.WaitFor(0) = wrSignaled then
      Break;

    Data := FSocks5.Receive(65536);
    if Length(Data) = 0 then
    begin
      if FSocks5.LastReceiveTimedOut then
      begin
        if (FMonitorControl <> nil) and ((GetTickCount64 - LastStreamProbeTick) >= 2000) then
        begin
          LastStreamProbeTick := GetTickCount64;
          try
            StreamAlive := FMonitorControl.HasLiveStreamTo(OwnerRef.FOnionAddress, OwnerRef.FOnionPort);
            if not StreamAlive then
              Break;
          except
            { If monitoring fails temporarily, keep the data channel alive. }
          end;
        end;
        Continue;
      end;
      Break; { Connection closed }
    end;

    { Copy data for the queued callback }
    DataCopy := Copy(Data);
    TThread.Queue(nil,
      procedure
      begin
        if Assigned(OwnerRef.FOnDataReceived) then
          OwnerRef.FOnDataReceived(OwnerRef, DataCopy);
      end);
  end;
end;

procedure TTorClientWorker.Execute;
var
  OwnerRef: TTorClientSocket;
begin
  OwnerRef := FOwner;

  try
    DoConnect;

    if not Terminated then
      DoReadLoop;
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

  SetOwnerState(tcsDisconnected);
  TThread.Queue(nil,
    procedure
    begin
      if Assigned(OwnerRef.FOnDisconnected) then
        OwnerRef.FOnDisconnected(OwnerRef);
    end);
end;

{ =========================================================================
  TTorClientSocket
  ========================================================================= }

constructor TTorClientSocket.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FLock := TCriticalSection.Create;
  FState := tcsDisconnected;
  FActive := False;
  FAutoStartTor := True;
  FSocksPort := TOR_DEFAULT_SOCKS_PORT;
  FControlPort := TOR_DEFAULT_CONTROL_PORT;
  FOnionPort := 80;
  FWorker := nil;
end;

destructor TTorClientSocket.Destroy;
begin
  DoStop;
  FreeAndNil(FLock);
  inherited;
end;

procedure TTorClientSocket.Loaded;
begin
  inherited;
  if FActive and not (csDesigning in ComponentState) then
    DoStart;
end;

procedure TTorClientSocket.SetActive(Value: Boolean);
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

procedure TTorClientSocket.SetOnionAddress(const Value: string);
begin
  if FActive and not (csDesigning in ComponentState) then
    raise Exception.Create('Cannot change OnionAddress while Active');
  FOnionAddress := Value;
end;

procedure TTorClientSocket.SetOnionPort(Value: Word);
begin
  if FActive and not (csDesigning in ComponentState) then
    raise Exception.Create('Cannot change OnionPort while Active');
  FOnionPort := Value;
end;

procedure TTorClientSocket.SetTorExePath(const Value: string);
begin
  if FActive and not (csDesigning in ComponentState) then
    raise Exception.Create('Cannot change TorExePath while Active');
  FTorExePath := Value;
end;

procedure TTorClientSocket.SetSocksPort(Value: Word);
begin
  if FActive and not (csDesigning in ComponentState) then
    raise Exception.Create('Cannot change SocksPort while Active');
  FSocksPort := Value;
end;

procedure TTorClientSocket.SetControlPort(Value: Word);
begin
  if FActive and not (csDesigning in ComponentState) then
    raise Exception.Create('Cannot change ControlPort while Active');
  FControlPort := Value;
end;

procedure TTorClientSocket.DoStart;
begin
  if FWorker <> nil then
    Exit;

  if FOnionAddress = '' then
    raise Exception.Create('OnionAddress is required');

  FActive := True;
  FState := tcsStartingTor;

  FWorker := TTorClientWorker.Create(Self);
  FWorker.Start;
end;

procedure TTorClientSocket.DoStop;
var
  FlushUntil: UInt64;
begin
  if FWorker <> nil then
  begin
    FWorker.SignalStop;

    { Close the SOCKS5 socket to unblock recv() }
    if FWorker.Socks5 <> nil then
      FWorker.Socks5.Disconnect;

    FWorker.WaitFor;
    FreeAndNil(FWorker);
  end;

  if GetCurrentThreadID = MainThreadID then
  begin
    FlushUntil := GetTickCount64 + 250;
    repeat
      CheckSynchronize(10);
    until GetTickCount64 >= FlushUntil;
  end;

  FActive := False;
  FState := tcsDisconnected;
end;

procedure TTorClientSocket.Connect;
begin
  SetActive(True);
end;

procedure TTorClientSocket.Disconnect;
begin
  SetActive(False);
end;

procedure TTorClientSocket.Send(const ABuf; ALen: Integer);
var
  SendFailed: Boolean;
  ErrorMsg: string;
begin
  SendFailed := False;
  ErrorMsg := '';

  FLock.Enter;
  try
    if (FWorker = nil) or (FWorker.Socks5 = nil) then
      raise Exception.Create('Not connected');
    try
      FWorker.Socks5.Send(ABuf, ALen);
    except
      on E: Exception do
      begin
        SendFailed := True;
        ErrorMsg := E.Message;
      end;
    end;
  finally
    FLock.Leave;
  end;

  if SendFailed then
  begin
    { If write fails, treat the connection as lost and tear down immediately. }
    DoStop;
    if Assigned(FOnError) then
      FOnError(Self, 'Connection lost while sending: ' + ErrorMsg);
  end;
end;

procedure TTorClientSocket.Send(const ABytes: TBytes);
begin
  if Length(ABytes) > 0 then
    Send(ABytes[0], Length(ABytes));
end;

procedure TTorClientSocket.Send(const AStr: string);
var
  Buf: TBytes;
begin
  Buf := TEncoding.UTF8.GetBytes(AStr);
  Send(Buf);
end;

procedure TTorClientSocket.NewIdentity;
var
  Control: TTorControlClient;
  CookiePath: string;
begin
  Control := TTorControlClient.Create(FControlPort);
  try
    Control.Connect;
    if FDataDirectory <> '' then
      CookiePath := IncludeTrailingPathDelimiter(FDataDirectory) + 'control_auth_cookie'
    else
      CookiePath := '';

    if not Control.AuthenticateAuto(CookiePath) then
      raise Exception.Create('Could not authenticate with TOR control port');

    if not Control.SignalNewNym then
      raise Exception.Create('SIGNAL NEWNYM failed');
  finally
    Control.Free;
  end;
end;

end.
