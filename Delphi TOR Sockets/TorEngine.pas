{ ============================================================================
  TorEngine.pas - TOR Network Engine
  ============================================================================
  Shared engine for TOR socket components. Manages tor.exe as a silent
  background process, provides SOCKS5 proxy protocol, TOR Control Protocol,
  and WinSock helper routines.

  There are Zero external dependencies - it is simply pure WinSock + Windows API calls!
  ============================================================================ }

unit TorEngine;
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
  Winapi.Winsock2;

const
  { SOCKS5 Protocol Constants (RFC 1928) }
  SOCKS5_VERSION             = $05;
  SOCKS5_CMD_CONNECT         = $01;
  SOCKS5_ATYP_IPV4           = $01;
  SOCKS5_ATYP_DOMAIN         = $03;
  SOCKS5_ATYP_IPV6           = $04;
  SOCKS5_AUTH_NONE            = $00;
  SOCKS5_AUTH_NOACCEPTABLE    = $FF;

  { SOCKS5 Reply Codes }
  SOCKS5_REP_SUCCESS          = $00;
  SOCKS5_REP_GENERAL_FAILURE  = $01;
  SOCKS5_REP_NOT_ALLOWED      = $02;
  SOCKS5_REP_NET_UNREACHABLE  = $03;
  SOCKS5_REP_HOST_UNREACHABLE = $04;
  SOCKS5_REP_REFUSED          = $05;
  SOCKS5_REP_TTL_EXPIRED      = $06;
  SOCKS5_REP_CMD_NOT_SUPPORTED = $07;
  SOCKS5_REP_ADDR_NOT_SUPPORTED = $08;

  { TOR Extended Onion Service Error Codes }
  SOCKS5_REP_HS_DESC_NOT_FOUND  = $F0;
  SOCKS5_REP_HS_DESC_INVALID    = $F1;
  SOCKS5_REP_HS_INTRO_FAILED    = $F2;
  SOCKS5_REP_HS_REND_FAILED     = $F3;
  SOCKS5_REP_HS_MISSING_AUTH    = $F4;
  SOCKS5_REP_HS_WRONG_AUTH      = $F5;
  SOCKS5_REP_HS_BAD_ADDRESS     = $F6;
  SOCKS5_REP_HS_INTRO_TIMEOUT   = $F7;

  { TOR Defaults }
  TOR_DEFAULT_SOCKS_PORT    = 9050;
  TOR_DEFAULT_CONTROL_PORT  = 9051;

  { Windows Process Creation }
  CREATE_NO_WINDOW_FLAG = $08000000;

type
  { TOR Bootstrap State }
  TTorBootstrapPhase = (
    tbpStarting,
    tbpConnectingDir,
    tbpHandshakeDir,
    tbpOneHopCircuit,
    tbpRequestingStatus,
    tbpLoadingStatus,
    tbpLoadingKeys,
    tbpRequestingDescriptors,
    tbpLoadingDescriptors,
    tbpConnectingGuard,
    tbpHandshakeGuard,
    tbpCircuitCreate,
    tbpDone
  );

  { SOCKS5 Reply Code to human-readable message }
  function Socks5ReplyToStr(ACode: Byte): string;

  { =========================================================================
    WinSock Helpers
    ========================================================================= }

  { Initialize WinSock (safe to call multiple times) }
  procedure EnsureWinSockInit;

  { Create a TCP socket connected to localhost:APort }
  function ConnectLocalhost(APort: Word): TSocket;

  { Send all bytes reliably }
  procedure SendAll(ASocket: TSocket; const ABuf; ALen: Integer);

  { Receive exactly ALen bytes }
  procedure RecvAll(ASocket: TSocket; var ABuf; ALen: Integer);

  { Receive a CRLF-terminated line (TOR Control Protocol) }
  function RecvLine(ASocket: TSocket): AnsiString;

  { Close a socket safely }
  procedure SafeCloseSocket(var ASocket: TSocket);

type
  { =========================================================================
    SOCKS5 Client - Connects through TOR's SOCKS5 proxy
    ========================================================================= }
  TSocks5Client = class
  private
    FSocket: TSocket;
    FProxyPort: Word;
    FLastReplyCode: Byte;
    FLastReceiveTimedOut: Boolean;
    procedure DoGreeting;
    procedure DoConnect(const ADomain: AnsiString; APort: Word);
  public
    constructor Create(AProxyPort: Word = TOR_DEFAULT_SOCKS_PORT);
    destructor Destroy; override;

    { Connect to a .onion address (or any domain) through TOR SOCKS5 proxy.
      After this call, the socket is tunneled - read/write directly. }
    procedure Connect(const AOnionAddress: string; APort: Word);

    { Disconnect }
    procedure Disconnect;

    { Send raw bytes over the tunneled connection }
    procedure Send(const ABuf; ALen: Integer); overload;
    procedure Send(const ABytes: TBytes); overload;
    procedure Send(const AStr: string); overload;

    { Receive raw bytes }
    function Receive(ABufSize: Integer = 65536): TBytes;

    { Direct socket access for advanced use }
    property Socket: TSocket read FSocket;

    { Check if connected }
    function IsConnected: Boolean;

    { Last SOCKS5 reply code from CONNECT (0 = success) }
    property LastReplyCode: Byte read FLastReplyCode;
    property LastReceiveTimedOut: Boolean read FLastReceiveTimedOut;
  end;

  { =========================================================================
    TOR Control Client - Communicates with TOR's Control Port
    ========================================================================= }

  { Result from ADD_ONION }
  TOnionServiceInfo = record
    ServiceID: string;    { 56-char base32 ID (without .onion) }
    OnionAddress: string; { Full address with .onion suffix }
    PrivateKey: string;   { ED25519-V3:<base64> key blob for reuse }
  end;

  TTorControlClient = class
  private
    FSocket: TSocket;
    FControlPort: Word;
    FAuthenticated: Boolean;
    procedure SendCommand(const ACmd: AnsiString);
    function ReadResponse(out ALines: TStringList): Integer;
    function SimpleCommand(const ACmd: string): Boolean;
  public
    constructor Create(AControlPort: Word = TOR_DEFAULT_CONTROL_PORT);
    destructor Destroy; override;

    { Connect to TOR control port }
    procedure Connect;

    { Disconnect }
    procedure Disconnect;

    { Authenticate with password }
    function Authenticate(const APassword: string): Boolean;

    { Authenticate with cookie file }
    function AuthenticateCookie(const ACookieFilePath: string): Boolean;

    { Authenticate by querying PROTOCOLINFO for supported methods/cookie file.
      Falls back to APreferredCookiePath when provided. }
    function AuthenticateAuto(const APreferredCookiePath: string = ''): Boolean;

    { Get bootstrap progress (0-100) }
    function GetBootstrapProgress: Integer;

    { Wait until TOR is fully bootstrapped (blocks with polling) }
    function WaitForBootstrap(ATimeoutMs: Cardinal = 120000): Boolean;

    { Create a new ephemeral hidden service.
      AVirtualPort = port on the .onion address
      ALocalPort = port on localhost to map to
      APrivateKey = empty for new key, or 'ED25519-V3:<base64>' to reuse }
    function AddOnion(AVirtualPort, ALocalPort: Word;
      const APrivateKey: string = ''): TOnionServiceInfo;

    { Remove a hidden service by ServiceID }
    function DelOnion(const AServiceID: string): Boolean;

    { Request a new TOR circuit (new identity) }
    function SignalNewNym: Boolean;

    { Check whether TOR reports a live stream to AHost:APort }
    function HasLiveStreamTo(const AHost: string; APort: Word): Boolean;

    { Get TOR version string }
    function GetVersion: string;

    { Send SIGNAL SHUTDOWN to tor }
    function SignalShutdown: Boolean;

    property Authenticated: Boolean read FAuthenticated;
  end;

  { =========================================================================
    TOR Process Manager - Starts/stops tor.exe silently
    ========================================================================= }
  TTorProcess = class
  private
    FTorExePath: string;
    FDataDirectory: string;
    FSocksPort: Word;
    FControlPort: Word;
    FControlPassword: string;
    FProcessHandle: THandle;
    FProcessId: DWORD;
    FRunning: Boolean;
    FTorrcPath: string;
    procedure WriteTorrc;
    procedure CleanupProcess;
  public
    constructor Create;
    destructor Destroy; override;

    { Start tor.exe silently in the background }
    procedure Start;

    { Stop tor.exe gracefully (control port signal, then terminate) }
    procedure Stop;

    { Check if tor.exe process is still running }
    function IsRunning: Boolean;

    { Path to tor.exe (auto-detected if empty) }
    property TorExePath: string read FTorExePath write FTorExePath;

    { Directory for TOR state/cache files }
    property DataDirectory: string read FDataDirectory write FDataDirectory;

    { SOCKS5 proxy port }
    property SocksPort: Word read FSocksPort write FSocksPort;

    { Control port }
    property ControlPort: Word read FControlPort write FControlPort;

    { Password for control port authentication }
    property ControlPassword: string read FControlPassword write FControlPassword;

    { Whether tor.exe is currently running }
    property Running: Boolean read FRunning;
  end;

implementation

var
  GWinSockInitialized: Boolean = False;
  GWSAData: TWSAData;

{ =========================================================================
  Utility
  ========================================================================= }

function Socks5ReplyToStr(ACode: Byte): string;
begin
  case ACode of
    SOCKS5_REP_SUCCESS:           Result := 'Success';
    SOCKS5_REP_GENERAL_FAILURE:   Result := 'General SOCKS server failure';
    SOCKS5_REP_NOT_ALLOWED:       Result := 'Connection not allowed by ruleset';
    SOCKS5_REP_NET_UNREACHABLE:   Result := 'Network unreachable';
    SOCKS5_REP_HOST_UNREACHABLE:  Result := 'Host unreachable';
    SOCKS5_REP_REFUSED:           Result := 'Connection refused';
    SOCKS5_REP_TTL_EXPIRED:       Result := 'TTL expired';
    SOCKS5_REP_CMD_NOT_SUPPORTED: Result := 'Command not supported';
    SOCKS5_REP_ADDR_NOT_SUPPORTED: Result := 'Address type not supported';
    SOCKS5_REP_HS_DESC_NOT_FOUND: Result := 'Onion service descriptor not found';
    SOCKS5_REP_HS_DESC_INVALID:   Result := 'Onion service descriptor invalid';
    SOCKS5_REP_HS_INTRO_FAILED:   Result := 'Onion service introduction failed';
    SOCKS5_REP_HS_REND_FAILED:    Result := 'Onion service rendezvous failed';
    SOCKS5_REP_HS_MISSING_AUTH:   Result := 'Missing client authorization for onion service';
    SOCKS5_REP_HS_WRONG_AUTH:     Result := 'Wrong client authorization for onion service';
    SOCKS5_REP_HS_BAD_ADDRESS:    Result := 'Bad onion address';
    SOCKS5_REP_HS_INTRO_TIMEOUT:  Result := 'Onion service introduction timed out';
  else
    Result := Format('Unknown SOCKS5 reply code: $%.2x', [ACode]);
  end;
end;

function ExtractControlValue(const ALine, AKey: string): string;
var
  P, I: Integer;
begin
  Result := '';
  P := Pos(AKey, ALine);
  if P <= 0 then
    Exit;

  Inc(P, Length(AKey));
  if P > Length(ALine) then
    Exit;

  if ALine[P] = '"' then
  begin
    Inc(P);
    while P <= Length(ALine) do
    begin
      if ALine[P] = '"' then
        Break;

      if (ALine[P] = '\') and (P < Length(ALine)) then
      begin
        Inc(P);
        case ALine[P] of
          '\', '"': Result := Result + ALine[P];
          'n': Result := Result + #10;
          'r': Result := Result + #13;
          't': Result := Result + #9;
        else
          Result := Result + ALine[P];
        end;
      end
      else
        Result := Result + ALine[P];

      Inc(P);
    end;
  end
  else
  begin
    I := P;
    while (I <= Length(ALine)) and (ALine[I] <> ' ') do
      Inc(I);
    Result := Copy(ALine, P, I - P);
  end;
end;

{ =========================================================================
  WinSock Helpers
  ========================================================================= }

procedure EnsureWinSockInit;
begin
  if not GWinSockInitialized then
  begin
    if WSAStartup($0202, GWSAData) <> 0 then
      raise Exception.Create('WSAStartup failed');
    GWinSockInitialized := True;
  end;
end;

function ConnectLocalhost(APort: Word): TSocket;
var
  Addr: TSockAddrIn;
begin
  EnsureWinSockInit;

  Result := Winapi.Winsock2.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if Result = INVALID_SOCKET then
    raise Exception.CreateFmt('socket() failed: %d', [WSAGetLastError]);

  FillChar(Addr, SizeOf(Addr), 0);
  Addr.sin_family := AF_INET;
  Addr.sin_port := htons(APort);
  Addr.sin_addr.S_addr := inet_addr('127.0.0.1');

  if Winapi.Winsock2.connect(Result, TSockAddr(Addr), SizeOf(Addr)) = SOCKET_ERROR then
  begin
    closesocket(Result);
    Result := INVALID_SOCKET;
    raise Exception.CreateFmt('connect() to 127.0.0.1:%d failed: %d',
      [APort, WSAGetLastError]);
  end;
end;

procedure SendAll(ASocket: TSocket; const ABuf; ALen: Integer);
var
  Sent, Total: Integer;
  P: PByte;
begin
  P := @ABuf;
  Total := 0;
  while Total < ALen do
  begin
    Sent := Winapi.Winsock2.send(ASocket, P^, ALen - Total, 0);
    if Sent <= 0 then
      raise Exception.CreateFmt('send() failed: %d', [WSAGetLastError]);
    Inc(P, Sent);
    Inc(Total, Sent);
  end;
end;

procedure RecvAll(ASocket: TSocket; var ABuf; ALen: Integer);
var
  Recvd, Total: Integer;
  P: PByte;
begin
  P := @ABuf;
  Total := 0;
  while Total < ALen do
  begin
    Recvd := recv(ASocket, P^, ALen - Total, 0);
    if Recvd <= 0 then
      raise Exception.CreateFmt('recv() failed (connection closed): %d', [WSAGetLastError]);
    Inc(P, Recvd);
    Inc(Total, Recvd);
  end;
end;

function RecvLine(ASocket: TSocket): AnsiString;
var
  Ch: AnsiChar;
  Res: Integer;
begin
  Result := '';
  while True do
  begin
    Res := recv(ASocket, Ch, 1, 0);
    if Res <= 0 then
      raise Exception.Create('Connection closed while reading line');
    if Ch = #10 then
      Break;
    if Ch <> #13 then
      Result := Result + Ch;
  end;
end;

procedure SafeCloseSocket(var ASocket: TSocket);
begin
  if ASocket <> INVALID_SOCKET then
  begin
    shutdown(ASocket, SD_BOTH);
    closesocket(ASocket);
    ASocket := INVALID_SOCKET;
  end;
end;

{ =========================================================================
  TSocks5Client
  ========================================================================= }

constructor TSocks5Client.Create(AProxyPort: Word);
begin
  inherited Create;
  FProxyPort := AProxyPort;
  FSocket := INVALID_SOCKET;
  FLastReplyCode := SOCKS5_REP_SUCCESS;
  FLastReceiveTimedOut := False;
end;

destructor TSocks5Client.Destroy;
begin
  Disconnect;
  inherited;
end;

procedure TSocks5Client.DoGreeting;
var
  Greeting: array[0..2] of Byte;
  Response: array[0..1] of Byte;
begin
  { Send: VER=5, NMETHODS=1, METHOD=NO_AUTH }
  Greeting[0] := SOCKS5_VERSION;
  Greeting[1] := $01;
  Greeting[2] := SOCKS5_AUTH_NONE;
  SendAll(FSocket, Greeting, 3);

  { Receive: VER, METHOD }
  RecvAll(FSocket, Response, 2);

  if Response[0] <> SOCKS5_VERSION then
    raise Exception.Create('SOCKS5 proxy returned invalid version');

  if Response[1] = SOCKS5_AUTH_NOACCEPTABLE then
    raise Exception.Create('SOCKS5 proxy: no acceptable authentication methods');

  if Response[1] <> SOCKS5_AUTH_NONE then
    raise Exception.CreateFmt('SOCKS5 proxy selected unexpected auth method: $%.2x',
      [Response[1]]);
end;

procedure TSocks5Client.DoConnect(const ADomain: AnsiString; APort: Word);
var
  Request: TBytes;
  DomainLen: Byte;
  Reply: array[0..3] of Byte;
  SkipBuf: array[0..255] of Byte;
  AddrLen: Integer;
begin
  DomainLen := Length(ADomain);
  if DomainLen = 0 then
    raise Exception.Create('Domain name cannot be empty');

  { Build CONNECT request }
  SetLength(Request, 4 + 1 + DomainLen + 2);
  Request[0] := SOCKS5_VERSION;      { VER }
  Request[1] := SOCKS5_CMD_CONNECT;  { CMD }
  Request[2] := $00;                 { RSV }
  Request[3] := SOCKS5_ATYP_DOMAIN;  { ATYP = DOMAINNAME }
  Request[4] := DomainLen;           { Domain length }
  Move(ADomain[1], Request[5], DomainLen);
  Request[5 + DomainLen]     := Hi(APort);  { Port high byte (big-endian) }
  Request[5 + DomainLen + 1] := Lo(APort);  { Port low byte }

  SendAll(FSocket, Request[0], Length(Request));

  { Read reply header: VER, REP, RSV, ATYP }
  RecvAll(FSocket, Reply, 4);
  FLastReplyCode := Reply[1];

  if Reply[0] <> SOCKS5_VERSION then
    raise Exception.Create('SOCKS5 reply: invalid version');

  if Reply[1] <> SOCKS5_REP_SUCCESS then
    raise Exception.CreateFmt('SOCKS5 CONNECT failed: %s (code $%.2x)',
      [Socks5ReplyToStr(Reply[1]), Reply[1]]);

  { Read and discard BND.ADDR + BND.PORT based on ATYP }
  case Reply[3] of
    SOCKS5_ATYP_IPV4:
      AddrLen := 4 + 2; { 4 bytes IPv4 + 2 bytes port }
    SOCKS5_ATYP_IPV6:
      AddrLen := 16 + 2; { 16 bytes IPv6 + 2 bytes port }
    SOCKS5_ATYP_DOMAIN:
    begin
      { Read domain length byte first }
      RecvAll(FSocket, SkipBuf[0], 1);
      AddrLen := SkipBuf[0] + 2; { domain + 2 bytes port }
    end;
  else
    AddrLen := 6; { assume IPv4+port as fallback }
  end;

  RecvAll(FSocket, SkipBuf, AddrLen);

  { Socket is now tunneled through TOR! }
end;

procedure TSocks5Client.Connect(const AOnionAddress: string; APort: Word);
var
  TimeoutMs: Integer;
begin
  Disconnect;
  FLastReplyCode := SOCKS5_REP_SUCCESS;
  FLastReceiveTimedOut := False;

  { Connect to the local TOR SOCKS5 proxy }
  FSocket := ConnectLocalhost(FProxyPort);
  try
    { SOCKS5 handshake }
    DoGreeting;
    { SOCKS5 CONNECT to .onion domain }
    DoConnect(AnsiString(AOnionAddress), APort);

    { Use a finite recv timeout so worker loops can poll liveness. }
    TimeoutMs := 1000;
    setsockopt(FSocket, SOL_SOCKET, SO_RCVTIMEO, @TimeoutMs, SizeOf(TimeoutMs));
  except
    Disconnect;
    raise;
  end;
end;

procedure TSocks5Client.Disconnect;
begin
  SafeCloseSocket(FSocket);
end;

procedure TSocks5Client.Send(const ABuf; ALen: Integer);
begin
  if FSocket = INVALID_SOCKET then
    raise Exception.Create('Not connected');
  SendAll(FSocket, ABuf, ALen);
end;

procedure TSocks5Client.Send(const ABytes: TBytes);
begin
  if Length(ABytes) > 0 then
    Send(ABytes[0], Length(ABytes));
end;

procedure TSocks5Client.Send(const AStr: string);
var
  Buf: TBytes;
begin
  Buf := TEncoding.UTF8.GetBytes(AStr);
  Send(Buf);
end;

function TSocks5Client.Receive(ABufSize: Integer): TBytes;
var
  Buf: TBytes;
  Recvd: Integer;
  LastErr: Integer;
begin
  if FSocket = INVALID_SOCKET then
    raise Exception.Create('Not connected');

  FLastReceiveTimedOut := False;

  SetLength(Buf, ABufSize);
  Recvd := recv(FSocket, Buf[0], ABufSize, 0);
  if Recvd = SOCKET_ERROR then
  begin
    LastErr := WSAGetLastError;
    if (LastErr = WSAETIMEDOUT) or (LastErr = WSAEWOULDBLOCK) then
      FLastReceiveTimedOut := True;
    SetLength(Result, 0);
    Exit;
  end;

  if Recvd = 0 then
  begin
    SetLength(Result, 0);
    Exit;
  end;
  SetLength(Buf, Recvd);
  Result := Buf;
end;

function TSocks5Client.IsConnected: Boolean;
begin
  Result := (FSocket <> INVALID_SOCKET);
end;

{ =========================================================================
  TTorControlClient
  ========================================================================= }

constructor TTorControlClient.Create(AControlPort: Word);
begin
  inherited Create;
  FControlPort := AControlPort;
  FSocket := INVALID_SOCKET;
  FAuthenticated := False;
end;

destructor TTorControlClient.Destroy;
begin
  Disconnect;
  inherited;
end;

procedure TTorControlClient.Connect;
begin
  Disconnect;
  FSocket := ConnectLocalhost(FControlPort);
  FAuthenticated := False;
end;

procedure TTorControlClient.Disconnect;
begin
  SafeCloseSocket(FSocket);
  FAuthenticated := False;
end;

procedure TTorControlClient.SendCommand(const ACmd: AnsiString);
var
  CmdLine: AnsiString;
begin
  if FSocket = INVALID_SOCKET then
    raise Exception.Create('Control port not connected');
  CmdLine := ACmd + #13#10;
  SendAll(FSocket, CmdLine[1], Length(CmdLine));
end;

function TTorControlClient.ReadResponse(out ALines: TStringList): Integer;
var
  Line: AnsiString;
  Code: Integer;
  LLines: TStringList;
begin
  LLines := TStringList.Create;
  try
    Result := -1;
    while True do
    begin
      Line := RecvLine(FSocket);
      if Length(Line) < 3 then
      begin
        Result := -1;
        Break;
      end;

      Code := StrToIntDef(string(Copy(Line, 1, 3)), -1);

      { Add the data portion (after "NNN " or "NNN-") }
      if Length(Line) > 4 then
        LLines.Add(string(Copy(Line, 5, MaxInt)))
      else
        LLines.Add('');

      { Space after code = final line of response }
      if (Length(Line) >= 4) and (Line[4] = ' ') then
      begin
        Result := Code;
        Break;
      end;

      { "NNN+" starts a multi-line data block ending with "." on its own line }
      if (Length(Line) >= 4) and (Line[4] = '+') then
      begin
        while True do
        begin
          Line := RecvLine(FSocket);
          if Line = '.' then
            Break;
          LLines.Add(string(Line));
        end;
      end;
    end;

    ALines := LLines;
  except
    LLines.Free;
    ALines := nil;
    raise;
  end;
end;

function TTorControlClient.SimpleCommand(const ACmd: string): Boolean;
var
  Lines: TStringList;
  Code: Integer;
begin
  SendCommand(AnsiString(ACmd));
  Code := ReadResponse(Lines);
  try
    Result := (Code = 250);
  finally
    Lines.Free;
  end;
end;

function TTorControlClient.Authenticate(const APassword: string): Boolean;
var
  Lines: TStringList;
  Code: Integer;
begin
  if APassword = '' then
    SendCommand('AUTHENTICATE')
  else
    SendCommand(AnsiString('AUTHENTICATE "' + APassword + '"'));

  Code := ReadResponse(Lines);
  try
    FAuthenticated := (Code = 250);
    Result := FAuthenticated;
  finally
    Lines.Free;
  end;
end;

function TTorControlClient.AuthenticateCookie(const ACookieFilePath: string): Boolean;
var
  FS: TFileStream;
  Cookie: TBytes;
  HexStr: string;
  I: Integer;
  Lines: TStringList;
  Code: Integer;
begin
  Result := False;
  if not FileExists(ACookieFilePath) then
    raise Exception.CreateFmt('Cookie file not found: %s', [ACookieFilePath]);

  { Read the 32-byte cookie }
  FS := TFileStream.Create(ACookieFilePath, fmOpenRead or fmShareDenyNone);
  try
    SetLength(Cookie, FS.Size);
    if FS.Size > 0 then
      FS.ReadBuffer(Cookie[0], FS.Size);
  finally
    FS.Free;
  end;

  { Hex-encode }
  HexStr := '';
  for I := 0 to Length(Cookie) - 1 do
    HexStr := HexStr + IntToHex(Cookie[I], 2);

  SendCommand(AnsiString('AUTHENTICATE ' + HexStr));
  Code := ReadResponse(Lines);
  try
    FAuthenticated := (Code = 250);
    Result := FAuthenticated;
  finally
    Lines.Free;
  end;
end;

function TTorControlClient.AuthenticateAuto(const APreferredCookiePath: string): Boolean;
var
  Lines: TStringList;
  Code, I: Integer;
  S: string;
  Methods: string;
  CookiePath: string;
begin
  Result := False;
  Methods := '';
  CookiePath := '';

  { Ask TOR which auth methods and cookie file path it is currently using }
  try
    SendCommand('PROTOCOLINFO 1');
    Code := ReadResponse(Lines);
    try
      if Code = 250 then
      begin
        for I := 0 to Lines.Count - 1 do
        begin
          S := Trim(Lines[I]);
          if Pos('AUTH ', S) = 1 then
          begin
            Methods := UpperCase(ExtractControlValue(S, 'METHODS='));
            CookiePath := ExtractControlValue(S, 'COOKIEFILE=');
            Break;
          end;
        end;
      end;
    finally
      Lines.Free;
    end;
  except
    { Ignore; fallback attempts below may still authenticate }
  end;

  if (APreferredCookiePath <> '') and FileExists(APreferredCookiePath) then
  begin
    try
      if AuthenticateCookie(APreferredCookiePath) then
        Exit(True);
    except
    end;
  end;

  if (CookiePath <> '') and (not SameText(CookiePath, APreferredCookiePath)) and
     FileExists(CookiePath) then
  begin
    try
      if AuthenticateCookie(CookiePath) then
        Exit(True);
    except
    end;
  end;

  if (Pos('NULL', Methods) > 0) or (Methods = '') then
  begin
    try
      if Authenticate('') then
        Exit(True);
    except
    end;
  end;

  FAuthenticated := False;
end;

function TTorControlClient.GetBootstrapProgress: Integer;
var
  Lines: TStringList;
  Code: Integer;
  I, P: Integer;
  S, Token: string;
begin
  Result := 0;
  SendCommand('GETINFO status/bootstrap-phase');
  Code := ReadResponse(Lines);
  try
    if Code = 250 then
    begin
      for I := 0 to Lines.Count - 1 do
      begin
        S := Lines[I];
        P := Pos('PROGRESS=', S);
        if P > 0 then
        begin
          Token := '';
          Inc(P, Length('PROGRESS='));
          while (P <= Length(S)) and CharInSet(S[P], ['0'..'9']) do
          begin
            Token := Token + S[P];
            Inc(P);
          end;
          Result := StrToIntDef(Token, 0);
          Break;
        end;
      end;
    end;
  finally
    Lines.Free;
  end;
end;

function TTorControlClient.WaitForBootstrap(ATimeoutMs: Cardinal): Boolean;
var
  StartTick: UInt64;
  Progress: Integer;
begin
  StartTick := GetTickCount64;
  repeat
    Progress := GetBootstrapProgress;
    if Progress >= 100 then
      Exit(True);
    Sleep(500);
  until (GetTickCount64 - StartTick) >= ATimeoutMs;
  Result := False;
end;

function TTorControlClient.AddOnion(AVirtualPort, ALocalPort: Word;
  const APrivateKey: string): TOnionServiceInfo;
var
  Cmd: string;
  Lines: TStringList;
  Code, I: Integer;
  S: string;
begin
  Result.ServiceID := '';
  Result.OnionAddress := '';
  Result.PrivateKey := '';

  if APrivateKey <> '' then
    Cmd := Format('ADD_ONION %s Flags=Detach Port=%d,127.0.0.1:%d',
      [APrivateKey, AVirtualPort, ALocalPort])
  else
    Cmd := Format('ADD_ONION NEW:ED25519-V3 Flags=Detach Port=%d,127.0.0.1:%d',
      [AVirtualPort, ALocalPort]);

  SendCommand(AnsiString(Cmd));
  Code := ReadResponse(Lines);
  try
    if Code <> 250 then
      raise Exception.CreateFmt('ADD_ONION failed (code %d): %s',
        [Code, Lines.Text]);

    for I := 0 to Lines.Count - 1 do
    begin
      S := Lines[I];
      if Pos('ServiceID=', S) = 1 then
        Result.ServiceID := Copy(S, Length('ServiceID=') + 1, MaxInt)
      else if Pos('PrivateKey=', S) = 1 then
        Result.PrivateKey := Copy(S, Length('PrivateKey=') + 1, MaxInt);
    end;

    if Result.ServiceID <> '' then
      Result.OnionAddress := Result.ServiceID + '.onion';
  finally
    Lines.Free;
  end;
end;

function TTorControlClient.DelOnion(const AServiceID: string): Boolean;
begin
  Result := SimpleCommand('DEL_ONION ' + AServiceID);
end;

function TTorControlClient.SignalNewNym: Boolean;
begin
  Result := SimpleCommand('SIGNAL NEWNYM');
end;

function TTorControlClient.HasLiveStreamTo(const AHost: string; APort: Word): Boolean;
var
  Lines: TStringList;
  Code, I, P, Space1, Space2: Integer;
  Line, Tail, State, TargetNeedle: string;
begin
  Result := False;
  TargetNeedle := LowerCase(AHost + ':' + IntToStr(APort));

  SendCommand('GETINFO stream-status');
  Code := ReadResponse(Lines);
  try
    if Code <> 250 then
      Exit(False);

    for I := 0 to Lines.Count - 1 do
    begin
      Line := Trim(Lines[I]);
      if Line = '' then
        Continue;

      { GETINFO returns stream-status=<stream line> }
      P := Pos('=', Line);
      if P > 0 then
        Line := Trim(Copy(Line, P + 1, MaxInt));

      if Pos(TargetNeedle, LowerCase(Line)) = 0 then
        Continue;

      { stream line format starts with: "<id> <status> ..." }
      Space1 := Pos(' ', Line);
      if Space1 <= 0 then
        Continue;
      Tail := Trim(Copy(Line, Space1 + 1, MaxInt));
      Space2 := Pos(' ', Tail);
      if Space2 <= 0 then
        Continue;
      State := UpperCase(Copy(Tail, 1, Space2 - 1));

      if (State <> 'CLOSED') and (State <> 'FAILED') and (State <> 'DETACHED') then
      begin
        Result := True;
        Break;
      end;
    end;
  finally
    Lines.Free;
  end;
end;

function TTorControlClient.GetVersion: string;
var
  Lines: TStringList;
  Code, I: Integer;
  S: string;
begin
  Result := '';
  SendCommand('GETINFO version');
  Code := ReadResponse(Lines);
  try
    if Code = 250 then
    begin
      for I := 0 to Lines.Count - 1 do
      begin
        S := Lines[I];
        if Pos('version=', S) = 1 then
        begin
          Result := Copy(S, Length('version=') + 1, MaxInt);
          Break;
        end;
      end;
    end;
  finally
    Lines.Free;
  end;
end;

function TTorControlClient.SignalShutdown: Boolean;
begin
  Result := SimpleCommand('SIGNAL SHUTDOWN');
end;

{ =========================================================================
  TTorProcess
  ========================================================================= }

constructor TTorProcess.Create;
begin
  inherited;
  FProcessHandle := 0;
  FProcessId := 0;
  FRunning := False;
  FSocksPort := TOR_DEFAULT_SOCKS_PORT;
  FControlPort := TOR_DEFAULT_CONTROL_PORT;
  FControlPassword := 'delphitor';
  FTorExePath := '';
  FDataDirectory := '';
end;

destructor TTorProcess.Destroy;
begin
  Stop;
  inherited;
end;

procedure TTorProcess.WriteTorrc;
var
  SL: TStringList;
  LogPath: string;
begin
  { Each TOR instance gets its own subdirectory based on SocksPort
    so that server (9050) and client (9060) don't collide }
  if FDataDirectory = '' then
    FDataDirectory := IncludeTrailingPathDelimiter(
      GetEnvironmentVariable('APPDATA')) + 'DelphiTor_' + IntToStr(FSocksPort);

  ForceDirectories(FDataDirectory);

  FTorrcPath := IncludeTrailingPathDelimiter(FDataDirectory) + 'torrc';
  LogPath := IncludeTrailingPathDelimiter(FDataDirectory) + 'tor.log';

  SL := TStringList.Create;
  try
    SL.Add('SocksPort ' + IntToStr(FSocksPort));
    SL.Add('ControlPort ' + IntToStr(FControlPort));
    SL.Add('CookieAuthentication 1');
    SL.Add('DataDirectory ' + FDataDirectory);
    SL.Add('Log notice file ' + LogPath);
    SL.SaveToFile(FTorrcPath);
  finally
    SL.Free;
  end;
end;

procedure TTorProcess.CleanupProcess;
begin
  if FProcessHandle <> 0 then
  begin
    CloseHandle(FProcessHandle);
    FProcessHandle := 0;
  end;
  FProcessId := 0;
  FRunning := False;
end;

procedure TTorProcess.Start;
var
  SI: TStartupInfo;
  PI: TProcessInformation;
  CmdLine: string;
  SearchPaths: array[0..3] of string;
  I: Integer;
begin
  if FRunning and IsRunning then
    Exit;

  CleanupProcess;

  { Auto-detect tor.exe if not specified... but i highly reccomend that you guys enter a direct Fully Qualified path like C:\myapp\tor.exe }
  if FTorExePath = '' then
  begin
    SearchPaths[0] := ExtractFilePath(ParamStr(0)) + 'tor.exe';
    SearchPaths[1] := ExtractFilePath(ParamStr(0)) + 'tor\tor.exe';
    SearchPaths[2] := ExtractFilePath(ParamStr(0)) + 'Tor\Browser\TorBrowser\Tor\tor.exe';
    SearchPaths[3] := 'tor.exe'; { PATH search }

    for I := 0 to High(SearchPaths) do
    begin
      if FileExists(SearchPaths[I]) then
      begin
        FTorExePath := SearchPaths[I];
        Break;
      end;
    end;

    if FTorExePath = '' then
      FTorExePath := ExtractFilePath(ParamStr(0)) + 'tor.exe';
  end;

  if not FileExists(FTorExePath) then
    raise Exception.CreateFmt('tor.exe not found at: %s', [FTorExePath]);

  { Write torrc configuration }
  WriteTorrc;

  { Launch tor.exe silently }
  FillChar(SI, SizeOf(SI), 0);
  SI.cb := SizeOf(TStartupInfo);
  SI.dwFlags := STARTF_USESHOWWINDOW;
  SI.wShowWindow := SW_HIDE;

  CmdLine := Format('"%s" -f "%s"', [FTorExePath, FTorrcPath]);

  FillChar(PI, SizeOf(PI), 0);

  if not CreateProcess(
    nil,
    PChar(CmdLine),
    nil,
    nil,
    False,
    CREATE_NO_WINDOW_FLAG,
    nil,
    PChar(ExtractFilePath(FTorExePath)),
    SI,
    PI
  ) then
    RaiseLastOSError;

  CloseHandle(PI.hThread);
  FProcessHandle := PI.hProcess;
  FProcessId := PI.dwProcessId;
  FRunning := True;
end;

procedure TTorProcess.Stop;
var
  Control: TTorControlClient;
  CookiePath: string;
begin
  if not FRunning then
    Exit;

  { Try graceful shutdown via control port first }
  try
    Control := TTorControlClient.Create(FControlPort);
    try
      Control.Connect;
      CookiePath := IncludeTrailingPathDelimiter(FDataDirectory) + 'control_auth_cookie';
      Control.AuthenticateAuto(CookiePath);
      Control.SignalShutdown;
      Control.Disconnect;
    finally
      Control.Free;
    end;

    { Wait up to 5 seconds for graceful exit }
    if FProcessHandle <> 0 then
      WaitForSingleObject(FProcessHandle, 5000);
  except
    { Graceful shutdown failed, proceed to force terminate }
  end;

  { Force terminate if still running }
  if IsRunning then
  begin
    if FProcessHandle <> 0 then
      TerminateProcess(FProcessHandle, 0);
    if FProcessHandle <> 0 then
      WaitForSingleObject(FProcessHandle, 3000);
  end;

  CleanupProcess;
end;

function TTorProcess.IsRunning: Boolean;
var
  ExitCode: DWORD;
begin
  if FProcessHandle = 0 then
    Exit(False);

  if GetExitCodeProcess(FProcessHandle, ExitCode) then
    Result := (ExitCode = STILL_ACTIVE)
  else
    Result := False;

  if not Result then
    FRunning := False;
end;

initialization

finalization
  if GWinSockInitialized then
    WSACleanup;

end.
