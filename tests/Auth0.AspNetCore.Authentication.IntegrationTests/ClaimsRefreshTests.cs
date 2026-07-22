using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json.Linq;
using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.IntegrationTests.Builders;
using Auth0.AspNetCore.Authentication.IntegrationTests.Extensions;
using Auth0.AspNetCore.Authentication.IntegrationTests.Infrastructure;
using Auth0.AspNetCore.Authentication.IntegrationTests.Utils;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    public class ClaimsRefreshTests
    {
        private readonly IConfiguration _configuration = TestConfiguration.GetConfiguration();

        /// <summary>
        /// Logs in (issuing an id_token with <paramref name="loginName"/>), then issues a
        /// /process request that forces a refresh. The refresh grant returns an id_token with
        /// <paramref name="refreshName"/>. Returns the parsed /process JSON ({ RefreshToken, Name }).
        /// A 120s leeway against a 70s token guarantees the refresh fires on the /process call.
        /// </summary>
        private async Task<JObject> RunRefreshAsync(
            string loginName,
            string refreshName,
            Action<Auth0WebAppWithAccessTokenOptions> configureAccessToken,
            HttpStatusCode refreshStatus = HttpStatusCode.OK,
            bool tamperRefreshSignature = false,
            string organization = null,
            string loginOrgId = null,
            string refreshOrgId = null,
            TimeSpan? maxAge = null,
            DateTime? loginAuthTime = null,
            DateTime? refreshAuthTime = null)
        {
            var nonce = "";
            var domain = _configuration["Auth0:Domain"];
            var clientId = _configuration["Auth0:ClientId"];

            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(
                    () => JwtUtils.GenerateToken(1, $"https://{domain}/", clientId, loginOrgId, nonce, DateTime.UtcNow.AddSeconds(70), loginName, loginAuthTime),
                    (me) => me.HasGrantType("authorization_code"))
                .MockToken(
                    () => tamperRefreshSignature
                        ? JwtUtils.GenerateToken(1, $"https://{domain}/", clientId, refreshOrgId, null, DateTime.UtcNow.AddSeconds(70), refreshName, refreshAuthTime) + "tampered"
                        : JwtUtils.GenerateToken(1, $"https://{domain}/", clientId, refreshOrgId, null, DateTime.UtcNow.AddSeconds(70), refreshName, refreshAuthTime),
                    (me) => me.HasGrantType("refresh_token"), 70, true, refreshStatus, "456_ROTATED")
                .Build();

            using var server = TestServerBuilder.CreateServer(opts =>
            {
                opts.ClientSecret = "123";
                opts.Backchannel = new HttpClient(mockHandler.Object);
                if (organization != null)
                {
                    opts.Organization = organization;
                }
                if (maxAge != null)
                {
                    opts.MaxAge = maxAge;
                }
            }, opts =>
            {
                opts.Audience = "123";
                opts.UseRefreshTokens = true;
                opts.AccessTokenExpirationLeeway = TimeSpan.FromSeconds(120);
                configureAccessToken(opts);
            });

            using var client = server.CreateClient();

            var loginResponse = await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}");
            var setCookie = Assert.Single(loginResponse.Headers, h => h.Key == "Set-Cookie");
            var queryParameters = UriUtils.GetQueryParams(loginResponse.Headers.Location);
            nonce = queryParameters["nonce"];
            var state = queryParameters["state"];

            var message = new HttpRequestMessage(HttpMethod.Get, $"{TestServerBuilder.Host}/{TestServerBuilder.Callback}?state={state}&nonce={nonce}&code=123");
            var callbackResponse = await client.SendAsync(message, setCookie.Value);
            callbackResponse.Headers.Location.OriginalString.Should().Be("/");

            var response = await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Process}", callbackResponse.Headers.GetValues("Set-Cookie"));
            return JObject.Parse(await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task Should_Rebuild_Principal_With_Full_Validation_When_Enabled()
        {
            var content = await RunRefreshAsync(
                loginName: "Old Name",
                refreshName: "New Name",
                configureAccessToken: opts =>
                {
                    opts.RebuildPrincipalOnRefresh = true;
                    opts.RefreshClaimsValidationType = RefreshClaimsValidationType.Full;
                });

            content.GetValue("Name").Value<string>().Should().Be("New Name");
        }

        [Fact]
        public async Task Should_Not_Rebuild_Principal_When_Flag_Off()
        {
            var content = await RunRefreshAsync(
                loginName: "Old Name",
                refreshName: "New Name",
                configureAccessToken: opts =>
                {
                    // RebuildPrincipalOnRefresh defaults to false; do not set it.
                });

            content.GetValue("RefreshToken").Value<string>().Should().Be("456_ROTATED");
            content.GetValue("Name").Value<string>().Should().Be("Old Name");
        }

        [Fact]
        public async Task Should_Rebuild_Principal_In_SkipSignature_Mode_Despite_Bad_Signature()
        {
            var content = await RunRefreshAsync(
                loginName: "Old Name",
                refreshName: "New Name",
                configureAccessToken: opts =>
                {
                    opts.RebuildPrincipalOnRefresh = true;
                    opts.RefreshClaimsValidationType = RefreshClaimsValidationType.SkipSignature;
                },
                tamperRefreshSignature: true);

            content.GetValue("Name").Value<string>().Should().Be("New Name");
        }

        [Fact]
        public async Task Should_Keep_Stale_Principal_When_Full_Validation_Fails()
        {
            // A rebuild failure must still fire OnTokensRefreshed: the refresh genuinely
            // succeeded (tokens are valid), only the principal rebuild was rejected.
            var eventFired = false;

            var content = await RunRefreshAsync(
                loginName: "Old Name",
                refreshName: "New Name",
                configureAccessToken: opts =>
                {
                    opts.RebuildPrincipalOnRefresh = true;
                    opts.RefreshClaimsValidationType = RefreshClaimsValidationType.Full;
                    opts.Events = new Auth0WebAppWithAccessTokenEvents
                    {
                        OnTokensRefreshed = (context) =>
                        {
                            eventFired = true;
                            return Task.CompletedTask;
                        }
                    };
                },
                tamperRefreshSignature: true);

            content.GetValue("RefreshToken").Value<string>().Should().Be("456_ROTATED");
            content.GetValue("Name").Value<string>().Should().Be("Old Name");
            eventFired.Should().BeTrue();
        }

        [Fact]
        public async Task Should_Keep_Stale_Principal_When_Refreshed_Token_Has_Mismatched_Organization()
        {
            // Login under org_123; the refresh grant returns an id_token for org_456.
            // The login-time organization constraint must be re-applied on refresh, so the
            // rebuild fails its business-rule check, the stale principal is kept, and the
            // refreshed tokens are still persisted.
            var content = await RunRefreshAsync(
                loginName: "Old Name",
                refreshName: "New Name",
                configureAccessToken: opts =>
                {
                    opts.RebuildPrincipalOnRefresh = true;
                    opts.RefreshClaimsValidationType = RefreshClaimsValidationType.SkipSignature;
                },
                organization: "org_123",
                loginOrgId: "org_123",
                refreshOrgId: "org_456");

            content.GetValue("RefreshToken").Value<string>().Should().Be("456_ROTATED");
            content.GetValue("Name").Value<string>().Should().Be("Old Name");
        }

        [Fact]
        public async Task Should_Fire_OnTokensRefreshed_On_Success_Independent_Of_Flag()
        {
            AccessTokenRefreshedContext captured = null;

            await RunRefreshAsync(
                loginName: "Old Name",
                refreshName: "New Name",
                configureAccessToken: opts =>
                {
                    opts.Events = new Auth0WebAppWithAccessTokenEvents
                    {
                        OnTokensRefreshed = (context) =>
                        {
                            captured = context;
                            return Task.CompletedTask;
                        }
                    };
                });

            captured.Should().NotBeNull();
            captured.RefreshToken.Should().Be("456_ROTATED");
            captured.AccessToken.Should().NotBeNullOrEmpty();
            captured.IdToken.Should().NotBeNullOrEmpty();
            captured.ExpiresAt.Should().BeAfter(DateTimeOffset.Now);
        }

        [Fact]
        public async Task Should_Rebuild_Principal_On_Refresh_Even_When_MaxAge_Window_Has_Elapsed()
        {
            // A refresh grant does not re-authenticate, so auth_time stays at the original login
            // time. With MaxAge set, that time is already outside the freshness window by the time
            // the refresh fires. The auth_time/MaxAge check is a login-freshness rule, not a claims
            // rule, so it must not block the rebuild on the refresh path.
            var content = await RunRefreshAsync(
                loginName: "Old Name",
                refreshName: "New Name",
                configureAccessToken: opts =>
                {
                    opts.RebuildPrincipalOnRefresh = true;
                    opts.RefreshClaimsValidationType = RefreshClaimsValidationType.Full;
                },
                maxAge: TimeSpan.FromSeconds(30),
                loginAuthTime: DateTime.UtcNow,
                refreshAuthTime: DateTime.UtcNow.AddSeconds(-300));

            content.GetValue("Name").Value<string>().Should().Be("New Name");
        }

        [Fact]
        public async Task Should_Map_Claim_Types_Consistently_In_SkipSignature_Mode()
        {
            // SkipSignature must run the refreshed token through the same validator as Full so the
            // inbound claim-type mapping matches the login path. NameIdentifier is the mapped form
            // of "sub"; if SkipSignature projected raw JWT claims it would be missing here.
            var content = await RunRefreshAsync(
                loginName: "Old Name",
                refreshName: "New Name",
                configureAccessToken: opts =>
                {
                    opts.RebuildPrincipalOnRefresh = true;
                    opts.RefreshClaimsValidationType = RefreshClaimsValidationType.SkipSignature;
                });

            content.GetValue("Name").Value<string>().Should().Be("New Name");
            content.GetValue("NameIdentifier").Value<string>().Should().Be("1");
        }

        [Fact]
        public async Task Should_Not_Fire_OnTokensRefreshed_When_Refresh_Fails()
        {
            var fired = false;

            await RunRefreshAsync(
                loginName: "Old Name",
                refreshName: "New Name",
                configureAccessToken: opts =>
                {
                    opts.Events = new Auth0WebAppWithAccessTokenEvents
                    {
                        OnTokensRefreshed = (context) =>
                        {
                            fired = true;
                            return Task.CompletedTask;
                        }
                    };
                },
                refreshStatus: HttpStatusCode.BadRequest);

            fired.Should().BeFalse();
        }
    }
}
