using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using static LibSSH.Interop;

namespace LibSSH
{
    public class SSHInstance : IDisposable
    {
        public IntPtr Session;
        public IntPtr Channel;
        public string Console = "";
        public SSHInstance()
        {
            Session = ssh_new();
        }
        public void Connect(string Host, string Username, string Password)
        {
            ssh_options_set(Session, SSH_OPTIONS_E.SSH_OPTIONS_HOST, Marshal.StringToHGlobalAnsi(Host));
            ssh_options_set(Session, SSH_OPTIONS_E.SSH_OPTIONS_USER, Marshal.StringToHGlobalAnsi(Username));
            ssh_options_set(Session, SSH_OPTIONS_E.SSH_OPTIONS_HMAC_C_S, Marshal.StringToHGlobalAnsi("hmac-sha1-96,hmac-md5,hmac-sha1,hmac-md5-96,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"));
            ssh_options_set(Session, SSH_OPTIONS_E.SSH_OPTIONS_HMAC_S_C, Marshal.StringToHGlobalAnsi("hmac-sha1-96,hmac-md5,hmac-sha1,hmac-md5-96,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"));
            ssh_options_set(Session, SSH_OPTIONS_E.SSH_OPTIONS_KEY_EXCHANGE, Marshal.StringToHGlobalAnsi("diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1,rsa-sha2-256,ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,sntrup761x25519-sha512@openssh.com,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256"));
            ssh_options_set(Session, SSH_OPTIONS_E.SSH_OPTIONS_HOSTKEYS, Marshal.StringToHGlobalAnsi("ssh-rsa,ssh-dss,ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256"));
            SSH_ERROR connect_result = ssh_connect(Session);
            if (connect_result != SSH_ERROR.SSH_OK) throw new LibSSHException(this, "Could not connect to host: " + connect_result.ToString());
            ssh_userauth_none(Session, IntPtr.Zero);
            SSH_AUTH_METHOD methods = ssh_userauth_list(Session, IntPtr.Zero);
            if (methods.HasFlag(SSH_AUTH_METHOD.SSH_AUTH_METHOD_PASSWORD))
            {
                if (ssh_userauth_password(Session, IntPtr.Zero, Marshal.StringToHGlobalAnsi(Password)) != SSH_AUTH_E.SSH_AUTH_SUCCESS)
                {
                    throw new LibSSHException(this, "Authentication failure.");
                }
            }
            else if(methods.HasFlag(SSH_AUTH_METHOD.SSH_AUTH_METHOD_INTERACTIVE))
            {
                SSH_AUTH_E auth_result = ssh_userauth_kbdint(Session, IntPtr.Zero, IntPtr.Zero);
                while (auth_result.HasFlag(SSH_AUTH_E.SSH_AUTH_INFO))
                {
                    string prompt = Marshal.PtrToStringAnsi(ssh_userauth_kbdint_getprompt(Session, 0));
                    if (prompt == null) throw new LibSSHException(this, "Bad password.");
                    if (prompt.ToLower().Contains("password"))
                    {
                        ssh_userauth_kbdint_setanswer(Session, 0, Marshal.StringToHGlobalAnsi(Password));
                    }
                    else
                    {
                        throw new LibSSHException(this, "No password prompt found.");
                    }
                    auth_result = ssh_userauth_kbdint(Session, IntPtr.Zero, IntPtr.Zero);
                }
                if (!auth_result.HasFlag(SSH_AUTH_E.SSH_AUTH_SUCCESS))
                {
                    throw new LibSSHException(this, "Authentication failure.");
                }
            }
            else
            {
                throw new LibSSHException(this, "Login method not supported.");
            }
            Channel = ssh_channel_new(Session);
            ssh_channel_open_session(Channel);
            ssh_channel_request_pty_size(Channel, Marshal.StringToHGlobalAnsi("vt100"), 160, 1000);
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
                sbytes = Regex.Replace(sbytes, @"\x1b\[1;0H", "\n");
                sbytes = Regex.Replace(sbytes, @"\x1b\[\??\d{1,4};?\d{0,4}\D?", "");
                result += sbytes;
                if (Regex.IsMatch(sbytes, ExpectRegex)) break;
            }
            Marshal.FreeHGlobal(buffer);
            Console += result;
            return result;
        }
        public void Send(string Text)
        {
            IntPtr text_ptr = Marshal.StringToHGlobalAnsi(Text);
            ssh_channel_write(Channel, text_ptr, (uint)Text.Length);
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
        private string rMessage;
        private string rError;
        public override string Message
        {
            get
            {
                return rMessage + "\r\n\r\n" + rError;
            }
        }
        public LibSSHException(SSHInstance Instance, string? message)
        {
            rMessage = message;
            IntPtr error_message = ssh_get_error(Instance.Session);
            rError = Marshal.PtrToStringAnsi(error_message);
            Instance.Dispose();
        }
    }
}