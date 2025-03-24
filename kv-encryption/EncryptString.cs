using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace Tt.FuncEncryption
{
    public class EncryptString
    {
        private readonly ILogger<EncryptString> _logger;

        public EncryptString(ILogger<EncryptString> logger)
        {
            _logger = logger;
        }

        [Function("EncryptString")]
        public IActionResult Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")] HttpRequest req)
        {
            _logger.LogInformation("C# HTTP trigger function processed a request.");
            return new OkObjectResult("Welcome to Azure Functions!");
        }
    }
}
