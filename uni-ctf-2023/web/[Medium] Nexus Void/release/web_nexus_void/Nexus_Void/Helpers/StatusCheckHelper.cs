using System.Diagnostics;

namespace Nexus_Void.Helpers
{
    public class StatusCheckHelper
    {
        public string output { get; set; }

        private string _command;

        public string command 
        {
            get { return _command; }

            set
            {
                _command = value;
                try
                {
                    var p = new System.Diagnostics.Process();

                    var processStartInfo = new ProcessStartInfo()
                    {
                        WindowStyle = ProcessWindowStyle.Hidden,
                        FileName = $"/bin/bash",
                        WorkingDirectory = "/tmp",
                        Arguments = $"-c \"{_command}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false
                    };
                    p.StartInfo = processStartInfo;
                    p.Start();

                    output = p.StandardOutput.ReadToEnd();
                }
                catch 
                {
                    output = "Something went wrong!";
                }
                
            }
        }


    }
}
