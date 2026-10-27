using RateMyAzureSubscriptions.Models;

namespace RateMyAzureSubscriptions.Services.Assessment;

/// <summary>
/// Microsoft Entra ID (100): Conditional Access &amp; MFA 35 · privileged access 20 · external collaboration 15 ·
/// user settings &amp; app governance 15 · authentication methods &amp; risk 15.
/// Caps: no MFA enforcement at all → max D · legacy authentication not blocked → max C.
/// </summary>
internal static class EntraAssessor
{
    public const string MfaCategory = "Conditional Access & MFA";
    public const string PrivilegedCategory = "Privileged access";
    public const string ExternalCategory = "External collaboration";
    public const string UserSettingsCategory = "User settings & app governance";
    public const string AuthMethodsCategory = "Authentication methods & risk";

    private static readonly string[] WeakMethods = ["Sms", "Voice"];
    private static readonly string[] StrongMethods = ["MicrosoftAuthenticator", "Fido2", "X509Certificate", "TemporaryAccessPass"];

    public static AreaRating Assess(AuditScanResult scan, FindingSink findings)
    {
        var area = AuditArea.EntraId;
        var t = scan.Entra;
        if (!t.IsAssessable)
            return RatingBuilder.NotAssessed(area, t.NotReadReason);

        var b = new RatingBuilder(area);
        var tenantName = string.IsNullOrEmpty(t.DisplayName) ? "Tenant" : t.DisplayName;
        var tenantRef = (name: tenantName, id: $"/tenants/{t.TenantId}");

        // ── 1. Conditional Access & MFA (35) ─────────────────────────────────
        var mfa = b.Category(MfaCategory, 35);
        var secDefaults = t.SecurityDefaultsEnabled == true;
        if (!t.ConditionalAccessReadable && !secDefaults)
        {
            mfa.Earned += 17;
            mfa.Details.Add("Conditional Access policies could not be read — half points awarded.");
        }
        else
        {
            var enabled = t.EnabledPolicies.Count();
            var reportOnly = t.ConditionalAccessPolicies.Count(p => p.IsReportOnly);
            if (t.ConditionalAccessReadable)
                mfa.Details.Add($"{t.ConditionalAccessPolicies.Count} Conditional Access polic{(t.ConditionalAccessPolicies.Count == 1 ? "y" : "ies")}: {enabled} enabled, {reportOnly} report-only.");
            if (secDefaults) mfa.Details.Add("Security defaults are enabled (MFA for everyone, legacy auth blocked).");

            if (secDefaults || t.HasMfaForAllUsers)
            {
                mfa.Earned += 15;
                mfa.Details.Add("MFA is required for all users on all cloud apps.");
            }
            else
            {
                mfa.Details.Add("No enabled policy requires MFA for all users on all cloud apps.");
                b.Improve("Create a Conditional Access policy requiring MFA for all users on all cloud apps.", 15, "nomfa");
                findings.Add(area, "High", "No MFA for all users", "No enabled Conditional Access policy requires multifactor authentication for all users.", tenantRef.name, tenantRef.id);
            }

            if (secDefaults || t.HasMfaForAdmins)
            {
                mfa.Earned += 10;
                mfa.Details.Add("MFA is required for administrator roles.");
            }
            else
            {
                mfa.Details.Add("No enabled policy requires MFA for directory roles.");
                b.Improve("Create a Conditional Access policy requiring phishing-resistant MFA for all admin roles.", 10, "nomfa");
                findings.Add(area, "High", "No MFA for admins", "No enabled Conditional Access policy requires MFA for privileged directory roles.", tenantRef.name, tenantRef.id);
            }

            if (!secDefaults && !t.HasMfaForAllUsers && !t.HasMfaForAdmins)
            {
                b.Cap("nomfa", "D", "Neither security defaults nor Conditional Access enforce multifactor authentication.");
                findings.Add(area, "High", "No MFA enforcement", "Security defaults are off and no Conditional Access policy enforces MFA.", tenantRef.name, tenantRef.id);
            }

            if (secDefaults || t.BlocksLegacyAuth)
            {
                mfa.Earned += 10;
                mfa.Details.Add("Legacy authentication is blocked.");
            }
            else
            {
                mfa.Details.Add("Legacy authentication clients are not blocked.");
                b.Cap("legacy", "C", "Legacy authentication protocols (which cannot do MFA) are not blocked.");
                b.Improve("Block legacy authentication for all users with a Conditional Access policy.", 10, "legacy");
                findings.Add(area, "High", "Legacy authentication allowed", "No enabled Conditional Access policy blocks legacy authentication clients (Exchange ActiveSync, other clients).", tenantRef.name, tenantRef.id);
            }

            foreach (var p in t.ConditionalAccessPolicies.Where(p => p.IsReportOnly))
                findings.Add(area, "Low", "Report-only policy", $"Conditional Access policy '{p.Name}' is in report-only mode ({p.Summary}).", p.Name, p.Id);
        }

        // ── 2. Privileged access (20) ────────────────────────────────────────
        var priv = b.Category(PrivilegedCategory, 20);
        if (!t.RolesReadable)
        {
            priv.Earned = 10;
            priv.Details.Add("Directory role membership could not be read — half points awarded.");
        }
        else
        {
            if (t.GlobalAdminCount is >= 2 and <= 5)
            {
                priv.Earned += 10;
                priv.Details.Add($"{t.GlobalAdminCount} Global Administrators (recommended 2–5).");
            }
            else if (t.GlobalAdminCount < 2)
            {
                priv.Earned += 5;
                priv.Details.Add($"{t.GlobalAdminCount} Global Administrator(s) — fewer than the recommended minimum of two.");
                b.Improve("Add a second Global Administrator (an emergency access account).", 5);
                findings.Add(area, "Medium", "Too few Global Administrators", $"Only {t.GlobalAdminCount} Global Administrator(s); a lockout has no fallback.", tenantRef.name, tenantRef.id);
            }
            else
            {
                priv.Details.Add($"{t.GlobalAdminCount} Global Administrators — more than the recommended maximum of five.");
                b.Improve($"Reduce Global Administrators from {t.GlobalAdminCount} to five or fewer.", 10);
                findings.Add(area, "Medium", "Too many Global Administrators", $"{t.GlobalAdminCount} accounts hold Global Administrator: {string.Join(", ", t.GlobalAdminNames.Take(8))}{(t.GlobalAdminNames.Count > 8 ? ", …" : "")}.", tenantRef.name, tenantRef.id);
            }

            if (t.GuestsInPrivilegedRoles == 0)
            {
                priv.Earned += 10;
                priv.Details.Add("No guest accounts hold privileged roles.");
            }
            else
            {
                priv.Details.Add($"{t.GuestsInPrivilegedRoles} guest account(s) hold privileged roles.");
                b.Improve($"Remove the {t.GuestsInPrivilegedRoles} guest account(s) from privileged directory roles.", 10);
                findings.Add(area, "High", "Guest in privileged role", $"{t.GuestsInPrivilegedRoles} guest (external) account(s) are members of privileged directory roles.", tenantRef.name, tenantRef.id);
            }
        }

        // ── 3. External collaboration (15) ───────────────────────────────────
        var ext = b.Category(ExternalCategory, 15);
        if (!t.AuthorizationPolicyReadable)
        {
            ext.Earned = 7;
            ext.Details.Add("The authorization policy could not be read — half points awarded.");
        }
        else
        {
            if (t.InvitesRestricted)
            {
                ext.Earned += 8;
                ext.Details.Add($"Guest invitations are restricted ({t.AllowInvitesFrom}).");
            }
            else
            {
                ext.Details.Add("Anyone, including guests, can invite guests.");
                b.Improve("Restrict guest invitations to administrators and the Guest Inviter role.", 8);
                findings.Add(area, "Medium", "Guest invites unrestricted", "Guest invitations are allowed from everyone, including existing guests.", tenantRef.name, tenantRef.id);
            }
            if (t.GuestAccessRestricted)
            {
                ext.Earned += 7;
                ext.Details.Add("Guest user access is restricted.");
            }
            else
            {
                ext.Details.Add("Guests have the same directory read access as members.");
                b.Improve("Set guest user access to 'restricted'.", 7);
                findings.Add(area, "Medium", "Guest permissions not restricted", "Guest users can read other users, groups and directory objects.", tenantRef.name, tenantRef.id);
            }
            if (t.GuestCount is { } guests && t.UserCount is { } users && users > 0)
                ext.Details.Add($"{guests} guest(s) among {users} user(s).");
        }

        // ── 4. User settings & app governance (15) ───────────────────────────
        var us = b.Category(UserSettingsCategory, 15);
        if (!t.AuthorizationPolicyReadable)
        {
            us.Earned = 7;
            us.Details.Add("The authorization policy could not be read — half points awarded.");
        }
        else
        {
            if (t.UsersCanRegisterApps == false) { us.Earned += 5; us.Details.Add("Users cannot register applications."); }
            else { us.Details.Add("Any user can register applications."); b.Improve("Prevent users from registering applications.", 5); findings.Add(area, "Low", "Users can register applications", "Any member can create app registrations.", tenantRef.name, tenantRef.id); }

            if (t.UsersCanCreateTenants == false) { us.Earned += 5; us.Details.Add("Users cannot create tenants."); }
            else { us.Details.Add("Any user can create new tenants."); b.Improve("Prevent users from creating tenants.", 5); findings.Add(area, "Low", "Users can create tenants", "Any member can create a new Entra tenant outside the organisation's controls.", tenantRef.name, tenantRef.id); }

            if (t.UserConsentAllowed == false) { us.Earned += 5; us.Details.Add("User consent to applications is restricted."); }
            else { us.Details.Add("Users can consent to applications accessing company data."); b.Improve("Restrict user consent to verified publishers / low-impact permissions.", 5); findings.Add(area, "Medium", "User consent allowed", "Users can grant third-party applications access to organisational data without admin approval.", tenantRef.name, tenantRef.id); }
        }

        // ── 5. Authentication methods & risk (15) ────────────────────────────
        var am = b.Category(AuthMethodsCategory, 15);
        if (t.ConditionalAccessReadable)
        {
            if (t.HasRiskPolicy) { am.Earned += 6; am.Details.Add("Risk-based Conditional Access is in place."); }
            else { am.Details.Add("No sign-in or user risk policy."); b.Improve("Add risk-based Conditional Access policies (requires Entra ID P2).", 6); findings.Add(area, "Low", "No risk-based policy", "No enabled Conditional Access policy responds to sign-in or user risk.", tenantRef.name, tenantRef.id); }

            if (t.HasDevicePolicy) { am.Earned += 5; am.Details.Add("Compliant or hybrid-joined devices are required for some access."); }
            else { am.Details.Add("No policy requires a compliant or managed device."); b.Improve("Require compliant devices for access to sensitive applications.", 5); findings.Add(area, "Low", "No device compliance policy", "No enabled Conditional Access policy requires a compliant or hybrid-joined device.", tenantRef.name, tenantRef.id); }
        }
        else
        {
            am.Earned += 5;
            am.Details.Add("Conditional Access policies could not be read — half points awarded for risk and device policies.");
        }

        if (!t.AuthMethodsReadable)
        {
            am.Earned += 2;
            am.Details.Add("The authentication methods policy could not be read — half points awarded.");
        }
        else
        {
            var weak = WeakMethods.Where(m => t.AuthMethods.TryGetValue(m, out var on) && on).ToList();
            var strong = StrongMethods.Where(m => t.AuthMethods.TryGetValue(m, out var on) && on).ToList();
            if (weak.Count == 0 && strong.Count > 0)
            {
                am.Earned += 4;
                am.Details.Add($"Strong methods enabled ({string.Join(", ", strong)}); SMS and voice are off.");
            }
            else
            {
                am.Earned += strong.Count > 0 ? 2 : 0;
                am.Details.Add(weak.Count > 0 ? $"Weak methods enabled: {string.Join(", ", weak)}." : "No strong (phishing-resistant) methods enabled.");
                b.Improve("Disable SMS/voice authentication and enable Authenticator, FIDO2 or certificate-based authentication.", 4 - (strong.Count > 0 ? 2 : 0));
                findings.Add(area, "Low", "Weak authentication methods", weak.Count > 0 ? $"SMS/voice authentication is enabled ({string.Join(", ", weak)})." : "No phishing-resistant authentication method is enabled.", tenantRef.name, tenantRef.id);
            }
        }

        var scope = $"tenant '{tenantName}'";
        if (t.ConditionalAccessReadable) scope += $", {t.ConditionalAccessPolicies.Count} CA polic{(t.ConditionalAccessPolicies.Count == 1 ? "y" : "ies")}";
        if (t.UserCount is { } uc) scope += $", {uc} users";
        return b.Build(1 + t.ConditionalAccessPolicies.Count, scope);
    }
}
