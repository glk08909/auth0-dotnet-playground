using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.IntegrationTests.Utils;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    public class PrincipalRefresherTests
    {
        private const string ClientId = "123";

        private static JsonWebKeySet LoadKeys()
        {
            var resourceName = "Auth0.AspNetCore.Authentication.IntegrationTests.jwks.json";
            using var stream = typeof(Startup).Assembly.GetManifestResourceStream(resourceName);
            using var reader = new StreamReader(stream!);
            return new JsonWebKeySet(reader.ReadToEnd());
        }

        /// <summary>
        /// Builds OpenIdConnectOptions that mirror how the SDK configures multiple-custom-domains
        /// mode: issuer validation is disabled (ValidateIssuer = false) because the real issuer is
        /// the per-request resolved domain, and ValidIssuer still points at the static primary
        /// domain. The signing keys are supplied directly so no ConfigurationManager is needed.
        /// </summary>
        private static OpenIdConnectOptions BuildMcdOidcOptions()
        {
            var keys = LoadKeys();

            // The SDK sources signing keys from the ConfigurationManager on the refresh path, so
            // provide a static one holding the test JWKS (mirrors production, where MCD always has
            // a ConfigurationManager configured).
            var configuration = new OpenIdConnectConfiguration();
            foreach (var key in keys.GetSigningKeys())
            {
                configuration.SigningKeys.Add(key);
            }

            var oidcOptions = new OpenIdConnectOptions
            {
                SecurityTokenValidator = new JwtSecurityTokenHandler(),
                ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration),
                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    ValidateAudience = true,
                    ValidAudience = ClientId,
                    // MCD disables static issuer validation on purpose.
                    ValidateIssuer = false,
                    ValidIssuer = "https://primary.example.com/",
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                }
            };
            return oidcOptions;
        }

        [Fact]
        public async Task RebuildAsync_With_CustomDomain_Issuer_Rebuilds_In_Full_Mode()
        {
            // The refreshed id_token is issued by the custom domain, not the static primary domain.
            // With issuer validation disabled (MCD), the refresher must resolve the issuer from the
            // principal's iss claim and still validate the token, rather than failing against the
            // static ValidIssuer.
            const string customDomainIssuer = "https://custom.example.com/";

            var currentPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[]
            {
                new Claim("iss", customDomainIssuer),
                new Claim("name", "Old Name"),
            }, "Test"));

            var refreshedIdToken = JwtUtils.GenerateToken(
                1, customDomainIssuer, ClientId, null, null, DateTime.UtcNow.AddSeconds(70), "New Name");

            var rebuilt = await PrincipalRefresher.RebuildAsync(
                refreshedIdToken,
                currentPrincipal,
                new Auth0WebAppOptions { Domain = "primary.example.com", ClientId = ClientId },
                BuildMcdOidcOptions(),
                RefreshClaimsValidationType.Full,
                new Dictionary<string, string?>(),
                new DefaultHttpContext(),
                CancellationToken.None);

            rebuilt.Should().NotBeNull();
            rebuilt!.FindFirst("name")?.Value.Should().Be("New Name");
        }

        [Fact]
        public async Task RebuildAsync_With_CustomDomain_Falls_Back_To_ResolvedDomain_When_Principal_Has_No_Iss()
        {
            // When the current principal carries no iss claim, the refresher falls back to the
            // domain resolved for the current request (stored in HttpContext.Items), matching how
            // the rest of the SDK resolves the issuer under custom domains.
            const string customDomainIssuer = "https://custom.example.com/";

            var currentPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[]
            {
                new Claim("name", "Old Name"),
            }, "Test"));

            var httpContext = new DefaultHttpContext();
            httpContext.Items[Auth0Constants.ResolvedDomainKey] = customDomainIssuer;

            var refreshedIdToken = JwtUtils.GenerateToken(
                1, customDomainIssuer, ClientId, null, null, DateTime.UtcNow.AddSeconds(70), "New Name");

            var rebuilt = await PrincipalRefresher.RebuildAsync(
                refreshedIdToken,
                currentPrincipal,
                new Auth0WebAppOptions { Domain = "primary.example.com", ClientId = ClientId },
                BuildMcdOidcOptions(),
                RefreshClaimsValidationType.Full,
                new Dictionary<string, string?>(),
                httpContext,
                CancellationToken.None);

            rebuilt.Should().NotBeNull();
            rebuilt!.FindFirst("name")?.Value.Should().Be("New Name");
        }
    }
}
