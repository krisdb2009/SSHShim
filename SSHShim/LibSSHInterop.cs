using System.Runtime.InteropServices;

namespace LibSSH
{
    public static class Interop
    {
        [DllImport("ssh")]
        public static extern IntPtr ssh_new();
        [DllImport("ssh")]
        public static extern IntPtr ssh_free(IntPtr session);
        [DllImport("ssh")]
        public static extern SSH_ERROR ssh_connect(IntPtr session);
        [DllImport("ssh")]
        public static extern SSH_AUTH_E ssh_userauth_none(IntPtr session, IntPtr username);
        [DllImport("ssh")]
        public static extern SSH_AUTH_METHOD ssh_userauth_list(IntPtr session, IntPtr username);
        [DllImport("ssh")]
        public static extern IntPtr ssh_get_error(IntPtr session_or_bind);
        [DllImport("ssh")]
        public static extern int ssh_channel_write(IntPtr channel, IntPtr data, uint len);
        [DllImport("ssh")]
        public static extern IntPtr ssh_get_issue_banner(IntPtr session);
        [DllImport("ssh")]
        public static extern void ssh_disconnect(IntPtr session);
        [DllImport("ssh")]
        public static extern bool ssh_is_connected(IntPtr session);
        [DllImport("ssh")]
        public static extern IntPtr ssh_channel_new(IntPtr session);
        [DllImport("ssh")]
        public static extern SSH_ERROR ssh_channel_request_shell(IntPtr session);
        [DllImport("ssh")]
        public static extern void ssh_channel_free(IntPtr channel);
        [DllImport("ssh")]
        public static extern SSH_AUTH_E ssh_userauth_kbdint(IntPtr session, IntPtr username, IntPtr submethods);
        [DllImport("ssh")]
        public static extern SSH_ERROR ssh_channel_request_pty_size(IntPtr channel, IntPtr terminal, int col, int row);
        [DllImport("ssh")]
        public static extern SSH_ERROR ssh_channel_open_session(IntPtr channel);
        [DllImport("ssh")]
        public static extern SSH_ERROR ssh_channel_close(IntPtr channel);
        [DllImport("ssh")]
        public static extern bool ssh_channel_is_open(IntPtr channel);
        [DllImport("ssh")]
        public static extern int ssh_channel_poll(IntPtr channel, bool is_stderr);
        [DllImport("ssh")]
        public static extern int ssh_channel_read_timeout(IntPtr channel, IntPtr dest, uint count, bool is_stderr, int timeout_ms);
        [DllImport("ssh")]
        public static extern SSH_AUTH_E ssh_userauth_password(IntPtr session, IntPtr username, IntPtr password);
        [DllImport("ssh")]
        public static extern int ssh_userauth_kbdint_setanswer(IntPtr session, uint i, IntPtr answer);
        [DllImport("ssh")]
        public static extern IntPtr ssh_userauth_kbdint_getprompt(IntPtr session, uint i, [Out, Optional] IntPtr echo);
        [DllImport("ssh")]
        public static extern int ssh_options_set(IntPtr session, SSH_OPTIONS_E type, IntPtr value);
        public enum SSH_OPTIONS_E
        {
            SSH_OPTIONS_HOST,
            SSH_OPTIONS_PORT,
            SSH_OPTIONS_PORT_STR,
            SSH_OPTIONS_FD,
            SSH_OPTIONS_USER,
            SSH_OPTIONS_SSH_DIR,
            SSH_OPTIONS_IDENTITY,
            SSH_OPTIONS_ADD_IDENTITY,
            SSH_OPTIONS_KNOWNHOSTS,
            SSH_OPTIONS_TIMEOUT,
            SSH_OPTIONS_TIMEOUT_USEC,
            SSH_OPTIONS_SSH1,
            SSH_OPTIONS_SSH2,
            SSH_OPTIONS_LOG_VERBOSITY,
            SSH_OPTIONS_LOG_VERBOSITY_STR,
            SSH_OPTIONS_CIPHERS_C_S,
            SSH_OPTIONS_CIPHERS_S_C,
            SSH_OPTIONS_COMPRESSION_C_S,
            SSH_OPTIONS_COMPRESSION_S_C,
            SSH_OPTIONS_PROXYCOMMAND,
            SSH_OPTIONS_BINDADDR,
            SSH_OPTIONS_STRICTHOSTKEYCHECK,
            SSH_OPTIONS_COMPRESSION,
            SSH_OPTIONS_COMPRESSION_LEVEL,
            SSH_OPTIONS_KEY_EXCHANGE,
            SSH_OPTIONS_HOSTKEYS,
            SSH_OPTIONS_GSSAPI_SERVER_IDENTITY,
            SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY,
            SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS,
            SSH_OPTIONS_HMAC_C_S,
            SSH_OPTIONS_HMAC_S_C,
            SSH_OPTIONS_PASSWORD_AUTH,
            SSH_OPTIONS_PUBKEY_AUTH,
            SSH_OPTIONS_KBDINT_AUTH,
            SSH_OPTIONS_GSSAPI_AUTH,
            SSH_OPTIONS_GLOBAL_KNOWNHOSTS,
            SSH_OPTIONS_NODELAY,
            SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
            SSH_OPTIONS_PROCESS_CONFIG,
            SSH_OPTIONS_REKEY_DATA,
            SSH_OPTIONS_REKEY_TIME
        }
        public enum SSH_ERROR
        {
            SSH_OK = 0,
            SSH_ERROR = -1,
            SSH_AGAIN = -2,
            SSH_EOF = -127
        }
        public enum SSH_AUTH_METHOD : uint
        {
            SSH_AUTH_METHOD_UNKNOWN = 0x0u,
            SSH_AUTH_METHOD_NONE = 0x1u,
            SSH_AUTH_METHOD_PASSWORD = 0x2u,
            SSH_AUTH_METHOD_PUBLICKEY = 0x4u,
            SSH_AUTH_METHOD_HOSTBASED = 0x8u,
            SSH_AUTH_METHOD_INTERACTIVE = 0x10u,
            SSH_AUTH_METHOD_GSSAPI_MIC = 0x20u
        }
        public enum SSH_AUTH_E
        {
            SSH_AUTH_SUCCESS = 0,
            SSH_AUTH_DENIED,
            SSH_AUTH_PARTIAL,
            SSH_AUTH_INFO,
            SSH_AUTH_AGAIN,
            SSH_AUTH_ERROR = -1
        }
    }
}