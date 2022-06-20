using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
//using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace VerifyAzureADToken.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private static readonly string TENANT_ID = "b7cf3d78-6cbd-4ac2-9956-f68ab60960bf";
        private static readonly string APPLICATION_ID = "373443fd-1110-443a-b448-107a0748c0cf";

        public AuthController(ILogger<AuthController> logger, IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        [HttpPost("Verify")]
        public async Task<ActionResult> Verify(TokenDto bodyData)
        {
            //// ambil public key dari microsoft
            //var httpRequestMessage = new HttpRequestMessage(
            //HttpMethod.Get,
            //$"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys")
            //{
            //};
            //var httpClient = _httpClientFactory.CreateClient();
            //var httpResponseMessage = await httpClient.SendAsync(httpRequestMessage);

            // Decode token
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadToken(bodyData.Token);
            var decoded = jsonToken as JwtSecurityToken;
            if(String.IsNullOrEmpty(bodyData.Token))
            {
                throw new Exception();
            }

            try
            {
                var isValid = ValidateToken(bodyData.Token);
                // continue business logic
                return Ok(decoded);
            }
            catch(Exception ex)
            {
                return Ok(ex.Message);
            }
        }

        private static bool ValidateToken(string authToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = GetValidationParameters();

            tokenHandler.ValidateToken(authToken, validationParameters, out SecurityToken validatedToken);
            return true;
        }



        private static TokenValidationParameters GetValidationParameters()
        {
            // key didapat dari 'https://login.microsoftonline.com/${process.env.TENANT_ID}/discovery/v2.0/keys'
            // disarankan untuk melakukan refetch key setiap hari dari microsoft
            // ambil string x5c yang kid = decoded.kid dan decoded.issuer = 'https://login.microsoftonline.com/{TENANT_ID}/v2.0'
            // contoh response ada di key.json file

            var strkey = "MIIDBTCCAe2gAwIBAgIQHsetP+i8i6VIAmjmfVGv6jANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIyMDEzMDIzMDYxNFoXDTI3MDEzMDIzMDYxNFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALKb0HF1qmKzHL3KkJn0jGJ21AvFNN2HLZ18iyAXtePDs4Qa4HQDpj3zHyYv7VFvC/bL1RqZOahunTdJ+uvXERyqlOdhpxtLZcmF5sxQtYcx1YEM/Xob3uLZSe7sPd+lyFDgDscd19tM3ace4JuMx8eI9mQZV7JAI+lN2naR0DbsFBOpJp4CVkfnXlpRIoDKUbL1FUNjuYdPkUqvFq/8e7ndyuhk7a8wEWps/bpNiF2rSmHZ4+Sa5Noy2Op1rfhrcZQP5fV8CKzpekqmv6ThiKUtNSSncSr6QQvVXUvKFwfuz+ai5LJr+7avkm24jnnNHL1O1j+71Eb9dOFeBYiP6qECAwEAAaMhMB8wHQYDVR0OBBYEFGzVFjAbYpU/2en4ry4LMLUHJ3GjMA0GCSqGSIb3DQEBCwUAA4IBAQBU0YdNVfdByvpwsPfwNdD8m1PLeeCKmLHQnWRI5600yEHuoUvoAJd5dwe1ZU1bHHRRKWN7AktUzofP3yF61xtizhEbyPjHK1tnR+iPEviWxVvK37HtfEPzuh1Vqp08bqY15McYUtf77l2HXTpak+UWYRYJBi++2umIDKY5UMqU+LEZnvaXybLUKN3xG4iy2q1Ab8syGFaUP7J3nCtVrR7ip39BnvSTTZZNo/OC7fYXJ2X4sN1/2ZhR5EtnAgwi2RvlZl0aWPrczArUCxDBCbsKPL/Up/kID1ir1VO4LT09ryfv2nx3y6l0YvuL7ePz4nGYCWHcbMVcUrQUXquZ3XtI";
            var certificate = new X509Certificate2(Convert.FromBase64String(strkey));

            return new TokenValidationParameters()
            {
                IssuerSigningKey = new X509SecurityKey(certificate),
                ValidAudience = APPLICATION_ID as string,
                ValidIssuer = $"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
            };
        }
    }
}
