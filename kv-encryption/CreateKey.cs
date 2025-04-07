using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;

namespace kv_encryption
{
    public class CreateKey
    {
        private readonly ILogger<CreateKey> _logger;

        public CreateKey(ILogger<CreateKey> logger)
        {
            _logger = logger;
        }

        [Function("EncryptWithKey")]
        public IActionResult Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")] HttpRequest req)
        {
            _logger.LogInformation("C# HTTP trigger function processed a request.");

            // Validate query parameters
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
            string keyName = req.Query["key"].FirstOrDefault();
            string text = req.Query["text"].FirstOrDefault();
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.

            if (string.IsNullOrEmpty(keyName) || string.IsNullOrEmpty(text))
            {
                _logger.LogError("Missing required query parameters 'key' and/or 'text'.");
                return new BadRequestObjectResult("Missing required query parameters 'key' and/or 'text'.");
            }

            // Create a new key client using the default credential from Azure.Identity using environment variables previously set,
            // including AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_TENANT_ID.
            var vaultUrl = Environment.GetEnvironmentVariable("VAULT_URL");
            if (string.IsNullOrEmpty(vaultUrl))
            {
                _logger.LogError("Environment variable 'VAULT_URL' is not set.");
                return new BadRequestObjectResult("Environment variable 'VAULT_URL' is not set.");
            }
            var client = new KeyClient(vaultUri: new Uri(vaultUrl), credential: new DefaultAzureCredential());

            KeyVaultKey key;
            try
            {
                // Try to retrieve the key using the key client.
                key = client.GetKey(keyName);
                _logger.LogInformation("Key '{KeyName}' already exists. Using the existing key.", keyName);
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 404)
            {
                // If the key does not exist, create a new key.
                _logger.LogInformation("Key '{KeyName}' does not exist. Creating a new key.", keyName);
                key = client.CreateKey(keyName, KeyType.Rsa);
            }

            // Create a new cryptography client using the same Key Vault or Managed HSM endpoint, service version,
            // and options as the KeyClient created earlier.
            var cryptoClient = client.GetCryptographyClient(key.Name, key.Properties.Version);

            byte[] plaintext = Encoding.UTF8.GetBytes(text);

            // encrypt the data using the algorithm RSAOAEP
            EncryptResult encryptResult = cryptoClient.Encrypt(EncryptionAlgorithm.RsaOaep, plaintext);

            // decrypt the encrypted data.
            DecryptResult decryptResult = cryptoClient.Decrypt(EncryptionAlgorithm.RsaOaep, encryptResult.Ciphertext);
            string decryptedText = Encoding.UTF8.GetString(decryptResult.Plaintext);


            return new OkObjectResult($"Welcome to Azure Functions! " + Environment.NewLine +
                $"+Encrypted Text: {Convert.ToBase64String(encryptResult.Ciphertext)}" + Environment.NewLine +
                $"+Encrypted Text: {decryptedText}");
        }


        [Function("HashText")]
        public IActionResult HashText([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")] HttpRequest req)
        {
            _logger.LogInformation("C# HTTP trigger function processed a request.");

            // Validate query parameters
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
            string keyName = req.Query["key"].FirstOrDefault();
            string text = req.Query["text"].FirstOrDefault();
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.

            if (string.IsNullOrEmpty(keyName) || string.IsNullOrEmpty(text))
            {
                _logger.LogError("Missing required query parameters 'key' and/or 'text'.");
                return new BadRequestObjectResult("Missing required query parameters 'key' and/or 'text'.");
            }

            // Create a new key client using the default credential from Azure.Identity
            var vaultUrl = Environment.GetEnvironmentVariable("VAULT_URL");
            if (string.IsNullOrEmpty(vaultUrl))
            {
                _logger.LogError("Environment variable 'VAULT_URL' is not set.");
                return new BadRequestObjectResult("Environment variable 'VAULT_URL' is not set.");
            }
            var client = new KeyClient(vaultUri: new Uri(vaultUrl), credential: new DefaultAzureCredential());

            KeyVaultKey key;
            try
            {
                // Try to retrieve the key using the key client.
                key = client.GetKey(keyName);
                _logger.LogInformation("Key '{KeyName}' already exists. Using the existing key.", keyName);
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 404)
            {
                _logger.LogError("Key '{KeyName}' does not exist.", keyName);
                return new BadRequestObjectResult($"Key '{keyName}' does not exist.");
            }

            // Use the key to create an HMAC hash
            byte[] keyBytes = key.Key.N; // Use the N property of JsonWebKey for the key bytes
            using var hmac = new HMACSHA256(keyBytes);
            byte[] textBytes = Encoding.UTF8.GetBytes(text);
            byte[] hashBytes = hmac.ComputeHash(textBytes);
            string hash = Convert.ToBase64String(hashBytes);

           // return new OkObjectResult($"Hashed Text: {hash}");

            return new OkObjectResult($"Welcome to Azure Functions! " + Environment.NewLine +
                $"Text To encrypt: {text}" + Environment.NewLine +
                $"Hashed Text: {hash}");
        }
    }
}
