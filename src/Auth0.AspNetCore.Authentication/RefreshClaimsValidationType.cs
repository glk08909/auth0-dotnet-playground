namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Controls how rigorously the refreshed <c>id_token</c> is validated before its claims
    /// replace the <see cref="System.Security.Claims.ClaimsPrincipal"/> when
    /// <see cref="Auth0WebAppWithAccessTokenOptions.RebuildPrincipalOnRefresh"/> is enabled.
    /// </summary>
    public enum RefreshClaimsValidationType
    {
        /// <summary>
        /// Validate the refreshed <c>id_token</c> signature against the cached JWKS, plus
        /// issuer, audience and lifetime, and the SDK's business-rule checks (sub, iat, azp, org).
        /// The <c>auth_time</c>/<c>MaxAge</c> login-freshness check is intentionally not applied
        /// on refresh, since a refresh grant does not re-authenticate the user. This is the
        /// default and the safe choice.
        /// </summary>
        Full,

        /// <summary>
        /// Skip <b>only</b> the cryptographic signature check (trusting the back-channel TLS
        /// exchange with the token endpoint). Issuer, audience and lifetime are still validated,
        /// and the SDK's business-rule checks (sub, iat, azp, org) still run, so the resulting
        /// claims are mapped identically to <see cref="Full"/>. Lower cost and lower fidelity
        /// than <see cref="Full"/>.
        /// </summary>
        SkipSignature
    }
}
