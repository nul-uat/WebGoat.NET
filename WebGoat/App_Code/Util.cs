using System;
using System.Diagnostics;
using log4net;
using System.Reflection;
using System.IO;
using System.Threading;

namespace OWASP.WebGoat.NET.App_Code
{
    public class Util
    {
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        
        /// <summary>
        /// Validates that the provided executable path is safe to execute.
        /// Ensures the path does not contain shell metacharacters or suspicious patterns.
        /// </summary>
        /// <param name="executablePath">The path to the executable to validate</param>
        /// <returns>True if the path is valid and safe, false otherwise</returns>
        private static bool IsValidExecutablePath(string executablePath)
        {
            if (string.IsNullOrWhiteSpace(executablePath))
                return false;

            // Check for shell metacharacters that could be used for command injection
            string[] dangerousPatterns = new[] { "&&", "||", ";", "|", "`", "$", "(", ")", "<", ">", "&", "\n", "\r" };
            foreach (var pattern in dangerousPatterns)
            {
                if (executablePath.Contains(pattern))
                {
                    log.Warn(string.Format("Blocked executable path containing dangerous character: {0}", pattern));
                    return false;
                }
            }

            // Verify the file exists
            if (!File.Exists(executablePath))
            {
                log.Warn(string.Format("Executable file not found: {0}", executablePath));
                return false;
            }

            // Block known shell interpreters to prevent attackers from using them as the executable
            string fileName = Path.GetFileName(executablePath);
            string[] blockedExecutables;
             
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                // Windows: case-insensitive comparison for shell interpreters
                blockedExecutables = new[] { "cmd.exe", "powershell.exe", "cmd", "powershell", 
                                            "cscript.exe", "wscript.exe", "mshta.exe", "bash.exe", 
                                            "sh.exe", "ksh.exe", "zsh.exe" };
                 
                foreach (var blocked in blockedExecutables)
                {
                    if (string.Equals(fileName, blocked, StringComparison.OrdinalIgnoreCase))
                    {
                        log.Warn(string.Format("Blocked shell interpreter executable: {0}", fileName));
                        return false;
                    }
                }
            }
            else
            {
                // Unix/Linux: case-sensitive comparison for shell interpreters
                blockedExecutables = new[] { "sh", "bash", "zsh", "ksh", "csh", "tcsh", "ash", "dash" };
                 
                foreach (var blocked in blockedExecutables)
                {
                    if (string.Equals(fileName, blocked, StringComparison.Ordinal))
                    {
                        log.Warn(string.Format("Blocked shell interpreter executable: {0}", fileName));
                        return false;
                    }
                }
            }

            return true;
        }
        
        public static int RunProcessWithInput(string cmd, string args, string input)
        {
            // Validate the executable path to prevent command injection
            if (!IsValidExecutablePath(cmd))
            {
                log.Error(string.Format("Invalid or unsafe executable path provided: {0}", cmd));
                throw new ArgumentException("Invalid executable path. The path contains invalid characters or the file does not exist.");
            }

            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                WorkingDirectory = Settings.RootDir,
                FileName = cmd,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
            };

            using (Process process = new Process())
            {
                process.EnableRaisingEvents = true;
                process.StartInfo = startInfo;

                process.OutputDataReceived += (sender, e) => {
                    if (e.Data != null)
                        log.Info(e.Data);
                };

                process.ErrorDataReceived += (sender, e) =>
                {
                    if (e.Data != null)
                        log.Error(e.Data);
                };

                AutoResetEvent are = new AutoResetEvent(false);

                process.Exited += (sender, e) => 
                {
                    Thread.Sleep(1000);
                    are.Set();
                    log.Info("Process exited");

                };

                process.Start();

                using (StreamReader reader = new StreamReader(new FileStream(input, FileMode.Open)))
                {
                    string line;
                    string replaced;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                            replaced = line.Replace("DB_Scripts/datafiles/", "DB_Scripts\\\\datafiles\\\\");
                        else
                            replaced = line;

                        log.Debug("Line: " + replaced);

                        process.StandardInput.WriteLine(replaced);
                    }
                }
    
                process.StandardInput.Close();
    

                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
    
                //NOTE: Looks like we have a mono bug: https://bugzilla.xamarin.com/show_bug.cgi?id=6291
                //have a wait time for now.
                
                are.WaitOne(10 * 1000);

                if (process.HasExited)
                    return process.ExitCode;
                else //WTF? Should have exited dammit!
                {
                    process.Kill();
                    return 1;
                }
            }
        }
    }
}

