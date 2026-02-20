unit TorSocketReg;

interface

procedure Register;

implementation

{$R TorSocketReg.dcr}

uses
  System.Classes,
  TorClientSocket,
  TorServerSocket;

procedure Register;
begin
  RegisterComponents('TOR Sockets', [TTorClientSocket, TTorServerSocket]);
end;

end.
