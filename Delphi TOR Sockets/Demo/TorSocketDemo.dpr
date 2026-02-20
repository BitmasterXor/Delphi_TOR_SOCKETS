program TorSocketDemo;

uses
  Vcl.Forms,
  MainForm in 'MainForm.pas' {FormMain},
  TorEngine in '..\TorEngine.pas',
  TorClientSocket in '..\TorClientSocket.pas',
  TorServerSocket in '..\TorServerSocket.pas';

{$R *.res}

begin
  ReportMemoryLeaksOnShutdown := True;
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.Title := 'TOR Socket Demo';
  Application.CreateForm(TFormMain, FormMain);
  Application.Run;
end.
