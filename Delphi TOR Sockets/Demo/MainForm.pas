unit MainForm;

interface

uses
  Winapi.Windows, Winapi.Messages,
  System.SysUtils, System.Classes,
  Vcl.Controls, Vcl.Forms, Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.ComCtrls,
  TorEngine, TorClientSocket, TorServerSocket;

type
  TFormMain = class(TForm)
    PageControl1: TPageControl;

    { Server Tab }
    TabServer: TTabSheet;
    LblServerStatus: TLabel;
    LblOnionAddr: TLabel;
    LblServerClients: TLabel;
    EditTorExePath: TEdit;
    LblTorExe: TLabel;
    EditVirtualPort: TEdit;
    LblVirtualPort: TLabel;
    EditLocalPort: TEdit;
    LblLocalPort: TLabel;
    BtnServerStart: TButton;
    BtnServerStop: TButton;
    MemoServerLog: TMemo;
    EditServerMsg: TEdit;
    BtnServerBroadcast: TButton;

    { Client Tab }
    TabClient: TTabSheet;
    LblClientStatus: TLabel;
    EditOnionAddress: TEdit;
    LblOnionAddress: TLabel;
    EditOnionPort: TEdit;
    LblOnionPort: TLabel;
    BtnClientConnect: TButton;
    BtnClientDisconnect: TButton;
    MemoClientLog: TMemo;
    EditClientMsg: TEdit;
    BtnClientSend: TButton;
    BtnNewIdentity: TButton;

    { Dropped Components }
    TorServer: TTorServerSocket;
    TorClient: TTorClientSocket;

    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure BtnServerStartClick(Sender: TObject);
    procedure BtnServerStopClick(Sender: TObject);
    procedure BtnServerBroadcastClick(Sender: TObject);
    procedure BtnClientConnectClick(Sender: TObject);
    procedure BtnClientDisconnectClick(Sender: TObject);
    procedure BtnClientSendClick(Sender: TObject);
    procedure BtnNewIdentityClick(Sender: TObject);

    { Server events }
    procedure ServerTorReady(Sender: TObject);
    procedure ServerOnionAddress(Sender: TObject);
    procedure ServerClientConnected(Sender: TObject; Client: TTorServerClient);
    procedure ServerClientDisconnected(Sender: TObject; Client: TTorServerClient);
    procedure ServerClientData(Sender: TObject; Client: TTorServerClient; const Data: TBytes);
    procedure ServerError(Sender: TObject; const ErrorMessage: string);

    { Client events }
    procedure ClientTorReady(Sender: TObject);
    procedure ClientConnected(Sender: TObject);
    procedure ClientDisconnected(Sender: TObject);
    procedure ClientDataReceived(Sender: TObject; const Data: TBytes);
    procedure ClientError(Sender: TObject; const ErrorMessage: string);
  private
    procedure LogServer(const Msg: string);
    procedure LogClient(const Msg: string);
  end;

var
  FormMain: TFormMain;

implementation

{$R *.dfm}

procedure TFormMain.FormCreate(Sender: TObject);
var
  BaseDir: string;
begin
  { Keep server/client TOR instances isolated to avoid lock-file collisions }
  BaseDir := IncludeTrailingPathDelimiter(GetEnvironmentVariable('APPDATA')) + 'DelphiTorDemo';
  TorServer.DataDirectory := IncludeTrailingPathDelimiter(BaseDir) + 'Server';
  TorClient.DataDirectory := IncludeTrailingPathDelimiter(BaseDir) + 'Client';
end;

procedure TFormMain.FormDestroy(Sender: TObject);
begin
  TorClient.Active := False;
  TorServer.Active := False;
end;

{ =========================================================================
  Server
  ========================================================================= }

procedure TFormMain.BtnServerStartClick(Sender: TObject);
begin
  TorServer.TorExePath := EditTorExePath.Text;
  TorServer.VirtualPort := StrToIntDef(EditVirtualPort.Text, 80);
  TorServer.LocalPort := StrToIntDef(EditLocalPort.Text, 8080);
  TorServer.Active := True;
  LblServerStatus.Caption := 'Status: Starting TOR...';
  LogServer('Starting TOR hidden service...');
  BtnServerStart.Enabled := False;
end;

procedure TFormMain.BtnServerStopClick(Sender: TObject);
begin
  TorServer.Active := False;
  LblServerStatus.Caption := 'Status: Inactive';
  LblOnionAddr.Caption := 'Onion Address: (not yet created)';
  LblServerClients.Caption := 'Connected Clients: 0';
  LogServer('Server stopped.');
  BtnServerStart.Enabled := True;
end;

procedure TFormMain.BtnServerBroadcastClick(Sender: TObject);
begin
  if EditServerMsg.Text <> '' then
  begin
    TorServer.Broadcast(EditServerMsg.Text);
    LogServer('Broadcast: ' + EditServerMsg.Text);
    EditServerMsg.Clear;
  end;
end;

procedure TFormMain.ServerTorReady(Sender: TObject);
begin
  LblServerStatus.Caption := 'Status: TOR Ready, Creating Hidden Service...';
  LogServer('TOR bootstrapped successfully!');
end;

procedure TFormMain.ServerOnionAddress(Sender: TObject);
begin
  LblServerStatus.Caption := 'Status: Listening';
  LblOnionAddr.Caption := 'Onion Address: ' + TorServer.OnionAddress;
  LogServer('Hidden service created: ' + TorServer.OnionAddress);
  LogServer('Private key (save to reuse address): ' + TorServer.PrivateKeyBlob);

  { Auto-fill client address for easy testing - I got tired of having to copy paste LOL! }
  EditOnionAddress.Text := TorServer.OnionAddress;
end;

procedure TFormMain.ServerClientConnected(Sender: TObject; Client: TTorServerClient);
begin
  LblServerClients.Caption := Format('Connected Clients: %d', [TorServer.ClientCount]);
  LogServer(Format('Client #%d connected', [Client.ID]));
end;

procedure TFormMain.ServerClientDisconnected(Sender: TObject; Client: TTorServerClient);
begin
  LblServerClients.Caption := Format('Connected Clients: %d', [TorServer.ClientCount]);
  LogServer(Format('Client #%d disconnected', [Client.ID]));
end;

procedure TFormMain.ServerClientData(Sender: TObject; Client: TTorServerClient;
  const Data: TBytes);
var
  S: string;
begin
  S := TEncoding.UTF8.GetString(Data);
  LogServer(Format('Client #%d says: %s', [Client.ID, S]));

  { Echo back }
  Client.Send('Echo: ' + S);
end;

procedure TFormMain.ServerError(Sender: TObject; const ErrorMessage: string);
begin
  LblServerStatus.Caption := 'Status: Error';
  LogServer('ERROR: ' + ErrorMessage);
  BtnServerStart.Enabled := True;
end;

{ =========================================================================
  Client
  ========================================================================= }

procedure TFormMain.BtnClientConnectClick(Sender: TObject);
begin
  TorClient.TorExePath := EditTorExePath.Text;
  TorClient.OnionAddress := EditOnionAddress.Text;
  TorClient.OnionPort := StrToIntDef(EditOnionPort.Text, 80);
  TorClient.Active := True;
  LblClientStatus.Caption := 'Status: Starting TOR...';
  LogClient('Connecting through TOR...');
  BtnClientConnect.Enabled := False;
end;

procedure TFormMain.BtnClientDisconnectClick(Sender: TObject);
begin
  TorClient.Active := False;
  LblClientStatus.Caption := 'Status: Disconnected';
  LogClient('Disconnected.');
  BtnClientConnect.Enabled := True;
end;

procedure TFormMain.BtnClientSendClick(Sender: TObject);
begin
  if EditClientMsg.Text <> '' then
  begin
    TorClient.Send(EditClientMsg.Text);
    LogClient('Sent: ' + EditClientMsg.Text);
    EditClientMsg.Clear;
  end;
end;

procedure TFormMain.BtnNewIdentityClick(Sender: TObject);
begin
  try
    TorClient.NewIdentity;
    LogClient('New identity requested (new TOR circuit).');
  except
    on E: Exception do
      LogClient('New identity failed: ' + E.Message);
  end;
end;

procedure TFormMain.ClientTorReady(Sender: TObject);
begin
  LblClientStatus.Caption := 'Status: TOR Ready, Connecting...';
  LogClient('TOR bootstrapped successfully!');
end;

procedure TFormMain.ClientConnected(Sender: TObject);
begin
  LblClientStatus.Caption := 'Status: Connected';
  LogClient('Connected to ' + TorClient.OnionAddress + '!');
  BtnClientConnect.Enabled := False;
end;

procedure TFormMain.ClientDisconnected(Sender: TObject);
begin
  LblClientStatus.Caption := 'Status: Disconnected';
  LogClient('Disconnected.');
  BtnClientConnect.Enabled := True;
end;

procedure TFormMain.ClientDataReceived(Sender: TObject; const Data: TBytes);
var
  S: string;
begin
  S := TEncoding.UTF8.GetString(Data);
  LogClient('Received: ' + S);
end;

procedure TFormMain.ClientError(Sender: TObject; const ErrorMessage: string);
begin
  LblClientStatus.Caption := 'Status: Error';
  LogClient('ERROR: ' + ErrorMessage);
  BtnClientConnect.Enabled := True;
end;

{ =========================================================================
  Logging
  ========================================================================= }

procedure TFormMain.LogServer(const Msg: string);
begin
  MemoServerLog.Lines.Add(FormatDateTime('hh:nn:ss', Now) + ' - ' + Msg);
end;

procedure TFormMain.LogClient(const Msg: string);
begin
  MemoClientLog.Lines.Add(FormatDateTime('hh:nn:ss', Now) + ' - ' + Msg);
end;

end.
