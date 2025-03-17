using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using FinalSFIntegration.Models;
using System.Security.Cryptography;

namespace FinalSFIntegration.Controllers
{
    public class AuthController : Controller
    {
        private readonly SalesforceSettings _salesforceSettings;

        public AuthController(IOptions<SalesforceSettings> salesforceSettings)
        {
            _salesforceSettings = salesforceSettings.Value;
        }

        // Step 1: Initiate Authentication
        public IActionResult Login()
        {
            string codeVerifier = GenerateCodeVerifier();
            string codeChallenge = GenerateCodeChallenge(codeVerifier);
            HttpContext.Session.SetString("CodeVerifier", codeVerifier);
            //var authorizeUrl = $"{_salesforceSettings.AuthorizeUrl}?" +
            //    $"response_type=code" +
            //    $"&client_id={_salesforceSettings.ClientId}" +
            //    $"&client_secret={_salesforceSettings.ClientSecret}" +
            //    $"&redirect_uri={Uri.EscapeDataString(_salesforceSettings.RedirectUri)}" +
            //    $"&scope=api+refresh_token" +
            //         $"&code_challenge={codeChallenge}" +
            //         $"&code_challenge_method=S256";
            var authorizeUrl = $"{_salesforceSettings.AuthorizeUrl}?" +
                $"response_type=code" +
                $"&client_id={_salesforceSettings.ClientId}" +
                $"&redirect_uri={Uri.EscapeDataString(_salesforceSettings.RedirectUri)}" +
                $"&scope=api+refresh_token";
            return Redirect(authorizeUrl);
        }

        // Step 2: Handle Callback and Exchange Code for Token
        public async Task<IActionResult> Callback(string code, string state)
        {
            if (string.IsNullOrEmpty(code))
            {
                return BadRequest("Authorization code is missing.");
            }
            string? codeVerifier = HttpContext.Session.GetString("CodeVerifier")?.ToString();
            //if (string.IsNullOrEmpty(codeVerifier))
            //{
            //    return Content("Error: Code verifier not found in session.");
            //}

            using var client = new HttpClient();
            var parameters = new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "code", code },
                { "client_id", _salesforceSettings.ClientId },
                { "client_secret", _salesforceSettings.ClientSecret },
                { "redirect_uri", _salesforceSettings.RedirectUri }
                //,
                //{"code_verifier",  codeVerifier}
            };

            var content = new FormUrlEncodedContent(parameters);
            var response = await client.PostAsync(_salesforceSettings.TokenUrl, content);

            if (response.IsSuccessStatusCode)
            {
                var responseBody = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonSerializer.Deserialize<SalesforceTokenResponse>(responseBody);

                // Store the token securely (e.g., in session, cookie, or database)
                HttpContext.Session.SetString("AccessToken", tokenResponse.access_token);
                HttpContext.Session.SetString("RefreshToken", tokenResponse.refresh_token ?? "");

                return RedirectToAction("Success");
            }
            else
            {
                var errorBody = await response.Content.ReadAsStringAsync();
                return Content($"Error: {response.StatusCode} - {errorBody}");
            }
        }

        // Success page (optional)
        public IActionResult Success()
        {
            var accessToken = HttpContext.Session.GetString("AccessToken");
            return Content($"Authentication successful! Access Token: {accessToken}");
        }

        private string GenerateCodeVerifier()
        {
            byte[] randomBytes = new byte[32]; // 32 bytes = 256 bits
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return Base64UrlEncode(randomBytes);
        }

        // Helper: Generate code challenge from verifier
        private string GenerateCodeChallenge(string codeVerifier)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                return Base64UrlEncode(challengeBytes);
            }
        }

        // Helper: Base64 URL encoding (no padding, replace + with -, / with _)
        private string Base64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
        }
    }

    // Class to deserialize the token response
    public class SalesforceTokenResponse
    {
        public string access_token { get; set; }
        public string refresh_token { get; set; }
        public string instance_url { get; set; }
        public string token_type { get; set; }
        public string issued_at { get; set; }
        public string signature { get; set; }
    }
}
