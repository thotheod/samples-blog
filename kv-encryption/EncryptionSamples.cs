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
    public class EncryptionSamples
    {
        private readonly ILogger<EncryptionSamples> _logger;

        public EncryptionSamples(ILogger<EncryptionSamples> logger)
        {
            _logger = logger;
        }

        private KeyClient SetupKeyClient()
        {
            var vaultUrl = Environment.GetEnvironmentVariable("VAULT_URL");
            if (string.IsNullOrEmpty(vaultUrl))
            {
                _logger.LogError("Environment variable 'VAULT_URL' is not set.");
                throw new InvalidOperationException("Environment variable 'VAULT_URL' is not set.");
            }
            return new KeyClient(vaultUri: new Uri(vaultUrl), credential: new DefaultAzureCredential());
        }

        [Function("CreateKey")]
        public IActionResult CreateKey([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")] HttpRequest req)
        {
            _logger.LogInformation("C# HTTP trigger function processed a request.");
            // Validate query parameters
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
            string keyName = req.Query["key"].FirstOrDefault();
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.

            if (string.IsNullOrEmpty(keyName))
            {
                _logger.LogError("Missing required query parameter 'key'.");
                return new BadRequestObjectResult("Missing required query parameters 'key'.");
            }

            // Use SetupKeyClient method to get the KeyClient
            var client = SetupKeyClient();

            // Additional logic for CreateKey function
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
                return new OkObjectResult($"Key '{key.Name}' of type '{key.KeyType}' created successfully.");
            }

            return new OkObjectResult($"Key '{keyName}' already exists.");
        }

        [Function("EncryptWithKey")]
        public IActionResult Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")] HttpRequest req)
        {
            _logger.LogInformation("C# HTTP trigger function - EncryptWithKey");

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

            // Use SetupKeyClient method to get the KeyClient
            var client = SetupKeyClient();

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
                _logger.LogInformation("Key '{KeyName}' does not exist.", keyName);
                return new BadRequestObjectResult($"Key {keyName} is not found.");
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

            return new OkObjectResult($"EncryptWithKey Function Call result: " + Environment.NewLine +
                $"Encrypted Text: {Convert.ToBase64String(encryptResult.Ciphertext)}" + Environment.NewLine +
                $"Decrypted Text: {decryptedText}");
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

            // Use SetupKeyClient method to get the KeyClient
            var client = SetupKeyClient();

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
            string hash = HashApiKey(text, key.Key.N);

            return new OkObjectResult($"HashText Function Call result: " + Environment.NewLine +
                $"Text To Hash: {text}" + Environment.NewLine +
                $"Hashed Text: {hash}");
        }

        public static string HashApiKey(string text, byte[] secretKey)
        {
            using var hmac = new HMACSHA256(secretKey);
            byte[] textBytes = Encoding.UTF8.GetBytes(text);
            byte[] hashBytes = hmac.ComputeHash(textBytes);
            return Convert.ToBase64String(hashBytes);
        }
    }
}
