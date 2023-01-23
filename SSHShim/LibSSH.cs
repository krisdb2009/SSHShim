using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using static LibSSH.Interop;

namespace LibSSH
{
    public class SSHInstance : IDisposable
    {
        IntPtr Session;
        IntPtr Channel;
        public SSHInstance()
        {
            Session = ssh_new();
        }
        public void Connect(string Host, string Username, string Password)
        {
            ssh_options_set(Session, SSH_OPTIONS_E.SSH_OPTIONS_HOST, Marshal.StringToHGlobalAnsi(Host));
            ssh_options_set(Session, SSH_OPTIONS_E.SSH_OPTIONS_USER, Marshal.StringToHGlobalAnsi(Username));
            SSH_ERROR connect_result = ssh_connect(Session);
            if (connect_result != SSH_ERROR.SSH_OK) throw new LibSSHException("Could not connect to host: " + connect_result.ToString());
            ssh_userauth_none(Session, IntPtr.Zero);
            SSH_AUTH_METHOD methods = ssh_userauth_list(Session, IntPtr.Zero);
            if (methods.HasFlag(SSH_AUTH_METHOD.SSH_AUTH_METHOD_INTERACTIVE))
            {
                SSH_AUTH_E auth_result = ssh_userauth_kbdint(Session, IntPtr.Zero, IntPtr.Zero);
                while (auth_result.HasFlag(SSH_AUTH_E.SSH_AUTH_INFO))
                {
                    string prompt = Marshal.PtrToStringAnsi(ssh_userauth_kbdint_getprompt(Session, 0));
                    if (prompt == null) throw new LibSSHException("Bad password.");
                    if (prompt.ToLower().Contains("password"))
                    {
                        ssh_userauth_kbdint_setanswer(Session, 0, Marshal.StringToHGlobalAnsi(Password));
                    } 
                    else
                    {
                        throw new LibSSHException("No password prompt found.");
                    }
                    auth_result = ssh_userauth_kbdint(Session, IntPtr.Zero, IntPtr.Zero);
                }
                if (!auth_result.HasFlag(SSH_AUTH_E.SSH_AUTH_SUCCESS))
                {
                    throw new LibSSHException("Authentication failure.");
                }
            }
            else
            {
                throw new LibSSHException("Interactive login not supported on remote host.");
            }
            Channel = ssh_channel_new(Session);
            ssh_channel_open_session(Channel);
            ssh_channel_request_shell(Channel);
        }
        public string Get(int TimeoutMS = -1, string ExpectRegex = ".*")
        {
            string result = "";
            IntPtr buffer = Marshal.AllocHGlobal(10240);
            while (ssh_channel_is_open(Channel))
            {
                int bytes_read = ssh_channel_read_timeout(Channel, buffer, 10240, false, TimeoutMS);
                if (bytes_read == 0) break;
                string sbytes = Marshal.PtrToStringAnsi(buffer, bytes_read);
                result += sbytes;
                if (Regex.IsMatch(result, ExpectRegex)) break;
            }
            Marshal.FreeHGlobal(buffer);
            return result;
        }
        public void Send(string Text)
        {
            IntPtr text_ptr = Marshal.StringToHGlobalAnsi(Text);
            ssh_channel_write(Channel, text_ptr, (uint)Text.Length);
        }
        public void Disconnect()
        {
            Dispose();
        }
        public void Dispose()
        {
            ssh_channel_close(Channel);
            ssh_channel_free(Channel);
            ssh_disconnect(Session);
            ssh_free(Session);
        }
    }
    public class LibSSHException : Exception
    {
        public LibSSHException(string? message) : base(message) { }
    }
}