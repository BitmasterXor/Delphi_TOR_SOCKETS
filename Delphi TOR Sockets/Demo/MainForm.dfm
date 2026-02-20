object FormMain: TFormMain
  Left = 0
  Top = 0
  Caption = 'TOR Socket Demo - Client & Server'
  ClientHeight = 580
  ClientWidth = 750
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  TextHeight = 15
  object PageControl1: TPageControl
    Left = 0
    Top = 0
    Width = 750
    Height = 580
    ActivePage = TabServer
    Align = alClient
    TabOrder = 0
    object TabServer: TTabSheet
      Caption = 'Server (Hidden Service)'
      object LblTorExe: TLabel
        Left = 16
        Top = 16
        Width = 65
        Height = 15
        Caption = 'tor.exe Path:'
      end
      object LblVirtualPort: TLabel
        Left = 16
        Top = 48
        Width = 62
        Height = 15
        Caption = 'Virtual Port:'
      end
      object LblLocalPort: TLabel
        Left = 250
        Top = 48
        Width = 56
        Height = 15
        Caption = 'Local Port:'
      end
      object LblServerStatus: TLabel
        Left = 16
        Top = 86
        Width = 86
        Height = 15
        Caption = 'Status: Inactive'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -12
        Font.Name = 'Segoe UI'
        Font.Style = [fsBold]
        ParentFont = False
      end
      object LblOnionAddr: TLabel
        Left = 16
        Top = 107
        Width = 171
        Height = 15
        Caption = 'Onion Address: (not yet created)'
      end
      object LblServerClients: TLabel
        Left = 16
        Top = 128
        Width = 109
        Height = 15
        Caption = 'Connected Clients: 0'
      end
      object EditTorExePath: TEdit
        Left = 100
        Top = 13
        Width = 430
        Height = 23
        TabOrder = 0
        Text = 'tor.exe'
      end
      object EditVirtualPort: TEdit
        Left = 100
        Top = 45
        Width = 60
        Height = 23
        TabOrder = 1
        Text = '80'
      end
      object EditLocalPort: TEdit
        Left = 320
        Top = 45
        Width = 60
        Height = 23
        TabOrder = 2
        Text = '8080'
      end
      object BtnServerStart: TButton
        Left = 550
        Top = 13
        Width = 90
        Height = 25
        Caption = 'Start Server'
        TabOrder = 3
        OnClick = BtnServerStartClick
      end
      object BtnServerStop: TButton
        Left = 646
        Top = 13
        Width = 90
        Height = 25
        Caption = 'Stop Server'
        TabOrder = 4
        OnClick = BtnServerStopClick
      end
      object MemoServerLog: TMemo
        Left = 16
        Top = 155
        Width = 718
        Height = 340
        ReadOnly = True
        ScrollBars = ssVertical
        TabOrder = 5
      end
      object EditServerMsg: TEdit
        Left = 16
        Top = 508
        Width = 590
        Height = 23
        TabOrder = 6
        TextHint = 'Type message to broadcast to all clients...'
      end
      object BtnServerBroadcast: TButton
        Left = 614
        Top = 506
        Width = 120
        Height = 25
        Caption = 'Broadcast'
        TabOrder = 7
        OnClick = BtnServerBroadcastClick
      end
    end
    object TabClient: TTabSheet
      Caption = 'Client (Connect to .onion)'
      ImageIndex = 1
      object LblClientStatus: TLabel
        Left = 16
        Top = 76
        Width = 117
        Height = 15
        Caption = 'Status: Disconnected'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -12
        Font.Name = 'Segoe UI'
        Font.Style = [fsBold]
        ParentFont = False
      end
      object LblOnionAddress: TLabel
        Left = 16
        Top = 16
        Width = 81
        Height = 15
        Caption = 'Onion Address:'
      end
      object LblOnionPort: TLabel
        Left = 16
        Top = 48
        Width = 25
        Height = 15
        Caption = 'Port:'
      end
      object EditOnionAddress: TEdit
        Left = 110
        Top = 13
        Width = 520
        Height = 23
        TabOrder = 0
        TextHint = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion'
      end
      object EditOnionPort: TEdit
        Left = 110
        Top = 45
        Width = 60
        Height = 23
        TabOrder = 1
        Text = '80'
      end
      object BtnClientConnect: TButton
        Left = 550
        Top = 45
        Width = 90
        Height = 25
        Caption = 'Connect'
        TabOrder = 2
        OnClick = BtnClientConnectClick
      end
      object BtnClientDisconnect: TButton
        Left = 646
        Top = 45
        Width = 90
        Height = 25
        Caption = 'Disconnect'
        TabOrder = 3
        OnClick = BtnClientDisconnectClick
      end
      object BtnNewIdentity: TButton
        Left = 200
        Top = 45
        Width = 110
        Height = 25
        Caption = 'New Identity'
        TabOrder = 4
        OnClick = BtnNewIdentityClick
      end
      object MemoClientLog: TMemo
        Left = 16
        Top = 105
        Width = 718
        Height = 390
        ReadOnly = True
        ScrollBars = ssVertical
        TabOrder = 5
      end
      object EditClientMsg: TEdit
        Left = 16
        Top = 508
        Width = 590
        Height = 23
        TabOrder = 6
        TextHint = 'Type message to send to server...'
      end
      object BtnClientSend: TButton
        Left = 614
        Top = 506
        Width = 120
        Height = 25
        Caption = 'Send'
        TabOrder = 7
        OnClick = BtnClientSendClick
      end
    end
  end
  object TorServer: TTorServerSocket
    OnClientConnected = ServerClientConnected
    OnClientDisconnected = ServerClientDisconnected
    OnClientData = ServerClientData
    OnError = ServerError
    OnTorReady = ServerTorReady
    OnOnionAddress = ServerOnionAddress
    Left = 288
    Top = 320
  end
  object TorClient: TTorClientSocket
    SocksPort = 9060
    ControlPort = 9061
    OnConnected = ClientConnected
    OnDisconnected = ClientDisconnected
    OnDataReceived = ClientDataReceived
    OnError = ClientError
    OnTorReady = ClientTorReady
    Left = 352
    Top = 320
  end
end
