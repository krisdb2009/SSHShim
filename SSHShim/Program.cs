using LibSSH;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/", async (request) => {

    request.Response.ContentType= "text/plain";

    SSHInstance instance = new();

    instance.Connect("", "", "");

    instance.Get();

    instance.Send("\r");

    instance.Get();
    
    instance.Send("no page\r");

    instance.Get();

    instance.Send("show run\rexpectdone\r");

    await request.Response.WriteAsync(instance.Get(10000, "expectdone"));

    instance.Disconnect();


});

app.Run();