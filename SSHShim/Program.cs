using LibSSH;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SSHShim
{
    public class SSHShim
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            var app = builder.Build();
            app.MapPost("/", async (hc) => {
                hc.Response.ContentType = "text/plain";
                string hostname = hc.Request.Form["hostname"];
                string username = hc.Request.Form["username"];
                string password = hc.Request.Form["password"];
                string commands = hc.Request.Form["commands"];
                if (
                    hostname == null ||
                    username == null ||
                    password == null ||
                    commands == null ||
                    hostname == "" ||
                    username == "" ||
                    password == "" ||
                    commands == ""
                ) throw new Exception("POST: 'hostname', 'username', 'password', or 'commands' missing.");
                SSHInstance instance = new();
                try 
                {
                    instance.Connect(hostname, username, password);
                    foreach (var command in commands.Split('\n'))
                    {
                        if (Regex.IsMatch(command, "^{.*}$"))
                        {
                            ParameterLine parameters = JsonSerializer.Deserialize<ParameterLine>(command);
                            instance.Get(parameters.TimeoutMS, parameters.Expect);
                        }
                        else
                        {
                            instance.Send(command + "\n");
                        }
                    }
                }
                finaly 
                {
                    instance.Dispose();
                }
                await hc.Response.WriteAsync(instance.Console);
            });
            app.Run();
        }
    }
    class ParameterLine
    {
        public int TimeoutMS { get; set; } = 30000;
        public string Expect { get; set; } = ".*";
    }
}
