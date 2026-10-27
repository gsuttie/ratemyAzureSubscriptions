using System.Text.RegularExpressions;

namespace RateMyAzureSubscriptions.Models;

/// <summary>Common identity of an Azure resource in the inventory.</summary>
public abstract class ResourceBase
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string ResourceGroup { get; set; } = string.Empty;
    public string SubscriptionId { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;
}

// ── Compute ──────────────────────────────────────────────────────────────────

public sealed class VirtualMachineInfo : ResourceBase
{
    public string Size { get; set; } = string.Empty;
    public string OsType { get; set; } = string.Empty;
    /// <summary>"running", "deallocated", "stopped" (stopped = still billed), or "" when unknown.</summary>
    public string PowerState { get; set; } = string.Empty;
    public List<string> Zones { get; set; } = new();
    public string? AvailabilitySetId { get; set; }
    public bool UsesManagedDisks { get; set; } = true;
    public bool BootDiagnosticsEnabled { get; set; }
    public bool HasManagedIdentity { get; set; }
    public string LicenseType { get; set; } = string.Empty;
    public List<string> NicIds { get; set; } = new();

    // Resolved after discovery
    public bool? IsBackedUp { get; set; }
    public bool HasPublicIp { get; set; }

    public bool IsZonalOrInSet => Zones.Count > 0 || AvailabilitySetId is not null;
    public bool IsStoppedNotDeallocated => PowerState.Equals("stopped", StringComparison.OrdinalIgnoreCase);
    public bool IsDeallocated => PowerState.Equals("deallocated", StringComparison.OrdinalIgnoreCase);
    public bool IsWindows => OsType.Equals("Windows", StringComparison.OrdinalIgnoreCase);
    public bool HasHybridBenefit => LicenseType.Contains("Windows_Server", StringComparison.OrdinalIgnoreCase) || LicenseType.Contains("RHEL", StringComparison.OrdinalIgnoreCase) || LicenseType.Contains("SLES", StringComparison.OrdinalIgnoreCase);

    /// <summary>Previous-generation sizes (Basic, A-series v1, D/DS v1 and v2, F/G v1) that have cheaper, faster successors.</summary>
    public bool IsPreviousGenerationSize =>
        Size.StartsWith("Basic_", StringComparison.OrdinalIgnoreCase) ||
        Regex.IsMatch(Size, @"^Standard_A\d+$", RegexOptions.IgnoreCase) ||
        Regex.IsMatch(Size, @"^Standard_(D|DS|G|GS|F|FS)\d+$", RegexOptions.IgnoreCase) ||
        Regex.IsMatch(Size, @"^Standard_(D|DS)\d+_v2$", RegexOptions.IgnoreCase);
}

public sealed class DiskInfo : ResourceBase
{
    public int SizeGb { get; set; }
    public string Sku { get; set; } = string.Empty;
    /// <summary>Attached, Unattached, Reserved, ActiveSAS…</summary>
    public string DiskState { get; set; } = string.Empty;
    public bool IsUnattached => DiskState.Equals("Unattached", StringComparison.OrdinalIgnoreCase);
}

public sealed class WebAppInfo : ResourceBase
{
    public string Kind { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public bool HttpsOnly { get; set; }
    public string MinTlsVersion { get; set; } = string.Empty;
    public string FtpsState { get; set; } = string.Empty;
    public bool? AlwaysOn { get; set; }
    public bool HasManagedIdentity { get; set; }
    public string? ServerFarmId { get; set; }
    public string PublicNetworkAccess { get; set; } = string.Empty;

    public bool IsFunctionApp => Kind.Contains("functionapp", StringComparison.OrdinalIgnoreCase);
    public string TypeLabel => IsFunctionApp ? "Function App" : "App Service";
    public bool TlsOk => string.IsNullOrEmpty(MinTlsVersion) || MinTlsVersion == "1.2" || MinTlsVersion == "1.3";
    public bool FtpsOk => string.IsNullOrEmpty(FtpsState) || FtpsState.Equals("Disabled", StringComparison.OrdinalIgnoreCase) || FtpsState.Equals("FtpsOnly", StringComparison.OrdinalIgnoreCase);
}

public sealed class AppServicePlanInfo : ResourceBase
{
    public string SkuTier { get; set; } = string.Empty;
    public string SkuName { get; set; } = string.Empty;
    public int Capacity { get; set; }
    public int NumberOfSites { get; set; }
    public bool ZoneRedundant { get; set; }

    public bool IsEmpty => NumberOfSites == 0;
    public bool IsFreeOrShared => SkuTier.Equals("Free", StringComparison.OrdinalIgnoreCase) || SkuTier.Equals("Shared", StringComparison.OrdinalIgnoreCase);
    public bool IsBasic => SkuTier.Equals("Basic", StringComparison.OrdinalIgnoreCase);
    public bool IsConsumption => SkuTier.Equals("Dynamic", StringComparison.OrdinalIgnoreCase);
    /// <summary>Tiers where a single instance is a single point of failure.</summary>
    public bool IsSingleInstanceProductionRisk => !IsConsumption && !IsFreeOrShared && !IsEmpty && Capacity <= 1 && !ZoneRedundant;
}

// ── Networking ───────────────────────────────────────────────────────────────

public sealed class VirtualNetworkInfo : ResourceBase
{
    public List<string> AddressSpaces { get; set; } = new();
    public bool DdosProtectionEnabled { get; set; }
    public List<SubnetInfo> Subnets { get; set; } = new();
    public int PeeringCount { get; set; }
}

public sealed class SubnetInfo
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string AddressPrefix { get; set; } = string.Empty;
    public string? NsgId { get; set; }
    public string? RouteTableId { get; set; }
    public bool HasDelegation { get; set; }

    /// <summary>Platform subnets that cannot or should not carry an NSG.</summary>
    public bool IsPlatformSubnet =>
        Name.Equals("GatewaySubnet", StringComparison.OrdinalIgnoreCase) ||
        Name.Equals("AzureFirewallSubnet", StringComparison.OrdinalIgnoreCase) ||
        Name.Equals("AzureFirewallManagementSubnet", StringComparison.OrdinalIgnoreCase) ||
        Name.Equals("RouteServerSubnet", StringComparison.OrdinalIgnoreCase) ||
        Name.Equals("AzureBastionSubnet", StringComparison.OrdinalIgnoreCase);
}

public sealed class NsgRuleInfo
{
    public string Name { get; set; } = string.Empty;
    public int Priority { get; set; }
    public string Direction { get; set; } = string.Empty;
    public string Access { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public List<string> Sources { get; set; } = new();
    public List<string> DestinationPorts { get; set; } = new();

    public bool IsInboundAllow => Direction.Equals("Inbound", StringComparison.OrdinalIgnoreCase) && Access.Equals("Allow", StringComparison.OrdinalIgnoreCase);
    public bool FromInternet => Sources.Any(s => s is "*" or "Internet" or "0.0.0.0/0" or "Any");

    /// <summary>Ports that must never be open to the Internet: SSH, RDP, WinRM, SQL, and "all".</summary>
    public bool OpensManagementPort => DestinationPorts.Any(p =>
        p == "*" || PortRangeContains(p, 22) || PortRangeContains(p, 3389) || PortRangeContains(p, 5985) || PortRangeContains(p, 5986) || PortRangeContains(p, 1433));

    public static bool PortRangeContains(string range, int port)
    {
        if (range == "*") return true;
        var parts = range.Split('-');
        if (parts.Length == 1) return int.TryParse(parts[0], out var p) && p == port;
        return int.TryParse(parts[0], out var lo) && int.TryParse(parts[1], out var hi) && port >= lo && port <= hi;
    }
}

public sealed class NsgInfo : ResourceBase
{
    public List<NsgRuleInfo> Rules { get; set; } = new();
    public int SubnetCount { get; set; }
    public int NicCount { get; set; }
    public bool IsOrphaned => SubnetCount + NicCount == 0;
    public List<NsgRuleInfo> RiskyRules => Rules.Where(r => r.IsInboundAllow && r.FromInternet && r.OpensManagementPort).ToList();
}

public sealed class PublicIpInfo : ResourceBase
{
    public string IpAddress { get; set; } = string.Empty;
    public string Sku { get; set; } = string.Empty;
    public string? AttachedToId { get; set; }
    public bool IsAttached => AttachedToId is not null;
}

public sealed class NetworkInterfaceInfo : ResourceBase
{
    public string? VirtualMachineId { get; set; }
    public List<string> PublicIpIds { get; set; } = new();
}

public sealed class PrivateEndpointInfo : ResourceBase
{
    public string? TargetResourceId { get; set; }
    public string GroupId { get; set; } = string.Empty;
}

public sealed class NetworkWatcherInfo : ResourceBase { }

public sealed class FlowLogInfo : ResourceBase
{
    public string TargetResourceId { get; set; } = string.Empty;
    public bool Enabled { get; set; }
}

public sealed class PrivateDnsZoneInfo : ResourceBase { }

// ── Storage ──────────────────────────────────────────────────────────────────

public sealed class StorageAccountInfo : ResourceBase
{
    public string Kind { get; set; } = string.Empty;
    public string SkuName { get; set; } = string.Empty;
    public string AccessTier { get; set; } = string.Empty;
    public bool? AllowBlobPublicAccess { get; set; }
    public bool SupportsHttpsTrafficOnly { get; set; } = true;
    public string MinimumTlsVersion { get; set; } = string.Empty;
    public bool? AllowSharedKeyAccess { get; set; }
    public string PublicNetworkAccess { get; set; } = string.Empty;
    public string NetworkDefaultAction { get; set; } = string.Empty;
    public bool InfrastructureEncryption { get; set; }
    public bool? AllowCrossTenantReplication { get; set; }
    public bool? DefaultToOAuthAuthentication { get; set; }
    public bool IsHierarchicalNamespace { get; set; }

    // From per-account ARM reads (null = could not be read)
    public bool? BlobSoftDeleteEnabled { get; set; }
    public int? BlobSoftDeleteDays { get; set; }
    public bool? ContainerSoftDeleteEnabled { get; set; }
    public bool? VersioningEnabled { get; set; }
    public bool? HasLifecyclePolicy { get; set; }

    public bool HasPrivateEndpoint { get; set; }

    public bool IsV1 => Kind.Equals("Storage", StringComparison.OrdinalIgnoreCase) || Kind.Equals("BlobStorage", StringComparison.OrdinalIgnoreCase);
    public bool TlsOk => MinimumTlsVersion.Equals("TLS1_2", StringComparison.OrdinalIgnoreCase) || MinimumTlsVersion.Equals("TLS1_3", StringComparison.OrdinalIgnoreCase);
    public bool PublicNetworkRestricted =>
        PublicNetworkAccess.Equals("Disabled", StringComparison.OrdinalIgnoreCase) ||
        NetworkDefaultAction.Equals("Deny", StringComparison.OrdinalIgnoreCase);
    public bool IsRedundant => !SkuName.Contains("LRS", StringComparison.OrdinalIgnoreCase);
    public string RedundancyLabel => SkuName.Contains('_') ? SkuName[(SkuName.IndexOf('_') + 1)..] : SkuName;
}

// ── Security ─────────────────────────────────────────────────────────────────

public sealed class KeyVaultInfo : ResourceBase
{
    public bool SoftDeleteEnabled { get; set; }
    public bool PurgeProtectionEnabled { get; set; }
    public bool RbacAuthorization { get; set; }
    public string PublicNetworkAccess { get; set; } = string.Empty;
    public string NetworkDefaultAction { get; set; } = string.Empty;
    public bool PublicNetworkRestricted =>
        PublicNetworkAccess.Equals("Disabled", StringComparison.OrdinalIgnoreCase) ||
        NetworkDefaultAction.Equals("Deny", StringComparison.OrdinalIgnoreCase);
}

public sealed class SqlServerInfo : ResourceBase
{
    public string MinimalTlsVersion { get; set; } = string.Empty;
    public string PublicNetworkAccess { get; set; } = string.Empty;
    public bool EntraOnlyAuthentication { get; set; }
    public bool HasEntraAdmin { get; set; }
    public bool TlsOk => MinimalTlsVersion is "1.2" or "1.3";
    public bool PublicNetworkRestricted => PublicNetworkAccess.Equals("Disabled", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Defender for Cloud, policy and logging state of one subscription.</summary>
public sealed class SubscriptionSecurityInfo
{
    public string SubscriptionId { get; set; } = string.Empty;

    /// <summary>Defender plan name → pricing tier ("Standard" = enabled, "Free" = off).</summary>
    public Dictionary<string, string> DefenderPlans { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public bool DefenderPlansReadable => DefenderPlans.Count > 0;
    public bool? SecurityContactConfigured { get; set; }
    public double? SecureScorePercent { get; set; }
    public int HealthyAssessments { get; set; }
    public int UnhealthyAssessments { get; set; }
    public int HighSeverityUnhealthy { get; set; }
    public bool AssessmentsAvailable => HealthyAssessments + UnhealthyAssessments > 0;

    public bool? ActivityLogExported { get; set; }
    public List<string> ActivityLogDestinations { get; set; } = new();
    public int LogAnalyticsWorkspaceCount { get; set; }

    public int PolicyAssignmentCount { get; set; }
    public bool HasSecurityBenchmarkAssignment { get; set; }
    public List<string> PolicyAssignmentNames { get; set; } = new();

    public bool IsPlanEnabled(string plan) => DefenderPlans.TryGetValue(plan, out var tier) && tier.Equals("Standard", StringComparison.OrdinalIgnoreCase);
    public int EnabledPlanCount => DefenderPlans.Count(p => p.Value.Equals("Standard", StringComparison.OrdinalIgnoreCase));
}

// ── Microsoft Entra ID ───────────────────────────────────────────────────────

public sealed class ConditionalAccessPolicyInfo
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    /// <summary>enabled, disabled, enabledForReportingButNotEnforced</summary>
    public string State { get; set; } = string.Empty;
    public List<string> GrantControls { get; set; } = new();
    public List<string> IncludeUsers { get; set; } = new();
    public List<string> IncludeRoles { get; set; } = new();
    public List<string> IncludeApplications { get; set; } = new();
    public List<string> ClientAppTypes { get; set; } = new();
    public List<string> SignInRiskLevels { get; set; } = new();
    public List<string> UserRiskLevels { get; set; } = new();
    public string? AuthenticationStrengthName { get; set; }

    public bool IsEnabled => State.Equals("enabled", StringComparison.OrdinalIgnoreCase);
    public bool IsReportOnly => State.Equals("enabledForReportingButNotEnforced", StringComparison.OrdinalIgnoreCase);
    public bool AppliesToAllUsers => IncludeUsers.Any(u => u.Equals("All", StringComparison.OrdinalIgnoreCase));
    public bool AppliesToAllApps => IncludeApplications.Any(a => a.Equals("All", StringComparison.OrdinalIgnoreCase));
    public bool RequiresMfa => GrantControls.Any(g => g.Equals("mfa", StringComparison.OrdinalIgnoreCase)) || AuthenticationStrengthName is not null;
    public bool Blocks => GrantControls.Any(g => g.Equals("block", StringComparison.OrdinalIgnoreCase));
    public bool TargetsLegacyAuth =>
        ClientAppTypes.Any(c => c.Equals("exchangeActiveSync", StringComparison.OrdinalIgnoreCase) || c.Equals("other", StringComparison.OrdinalIgnoreCase)) &&
        !ClientAppTypes.Any(c => c.Equals("all", StringComparison.OrdinalIgnoreCase));
    public bool TargetsAdminRoles => IncludeRoles.Count > 0;
    public bool RequiresCompliantDevice => GrantControls.Any(g => g.Equals("compliantDevice", StringComparison.OrdinalIgnoreCase) || g.Equals("domainJoinedDevice", StringComparison.OrdinalIgnoreCase));
    public bool IsRiskBased => SignInRiskLevels.Count > 0 || UserRiskLevels.Count > 0;

    public string Summary
    {
        get
        {
            var parts = new List<string>();
            parts.Add(AppliesToAllUsers ? "all users" : TargetsAdminRoles ? $"{IncludeRoles.Count} admin role(s)" : $"{IncludeUsers.Count} user/group target(s)");
            if (Blocks) parts.Add("block");
            else if (AuthenticationStrengthName is not null) parts.Add($"strength: {AuthenticationStrengthName}");
            else if (GrantControls.Count > 0) parts.Add(string.Join("+", GrantControls));
            if (TargetsLegacyAuth) parts.Add("legacy auth clients");
            if (IsRiskBased) parts.Add("risk-based");
            return string.Join(" · ", parts);
        }
    }
}

public sealed class EntraTenantInfo
{
    public string TenantId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string DefaultDomain { get; set; } = string.Empty;

    /// <summary>Set when Microsoft Graph could not be read at all; the area is then "not assessed".</summary>
    public string? ReadError { get; set; }
    public List<string> Warnings { get; set; } = new();

    public bool? SecurityDefaultsEnabled { get; set; }
    public List<ConditionalAccessPolicyInfo> ConditionalAccessPolicies { get; set; } = new();
    public bool ConditionalAccessReadable { get; set; }

    // Authorization policy
    public bool AuthorizationPolicyReadable { get; set; }
    public string AllowInvitesFrom { get; set; } = string.Empty;
    public string GuestUserRoleId { get; set; } = string.Empty;
    public bool? UsersCanRegisterApps { get; set; }
    public bool? UsersCanCreateTenants { get; set; }
    public bool? UsersCanCreateSecurityGroups { get; set; }
    public bool? UserConsentAllowed { get; set; }

    // Privileged roles
    public bool RolesReadable { get; set; }
    public int GlobalAdminCount { get; set; }
    public List<string> GlobalAdminNames { get; set; } = new();
    public int GuestsInPrivilegedRoles { get; set; }
    public int PrivilegedRoleMemberCount { get; set; }

    // Users
    public int? UserCount { get; set; }
    public int? GuestCount { get; set; }

    // Authentication methods policy: method → enabled?
    public bool AuthMethodsReadable { get; set; }
    public Dictionary<string, bool> AuthMethods { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public const string RestrictedGuestRole = "2af84b1e-32c8-42b7-82bc-daa82404023b";
    public const string LimitedGuestRole = "10dae51f-b6af-4016-8d66-8c2a99b929b3";
    public bool GuestAccessRestricted => GuestUserRoleId.Equals(RestrictedGuestRole, StringComparison.OrdinalIgnoreCase) || GuestUserRoleId.Equals(LimitedGuestRole, StringComparison.OrdinalIgnoreCase);
    public bool InvitesRestricted => !string.IsNullOrEmpty(AllowInvitesFrom) && !AllowInvitesFrom.Equals("everyone", StringComparison.OrdinalIgnoreCase);

    public IEnumerable<ConditionalAccessPolicyInfo> EnabledPolicies => ConditionalAccessPolicies.Where(p => p.IsEnabled);
    public bool HasMfaForAllUsers => EnabledPolicies.Any(p => p.AppliesToAllUsers && p.AppliesToAllApps && p.RequiresMfa && !p.TargetsLegacyAuth);
    public bool HasMfaForAdmins => HasMfaForAllUsers || EnabledPolicies.Any(p => p.TargetsAdminRoles && p.RequiresMfa);
    public bool BlocksLegacyAuth => EnabledPolicies.Any(p => p.TargetsLegacyAuth && p.Blocks && p.AppliesToAllUsers);
    public bool HasRiskPolicy => EnabledPolicies.Any(p => p.IsRiskBased);
    public bool HasDevicePolicy => EnabledPolicies.Any(p => p.RequiresCompliantDevice);
    /// <summary>True when Graph was reachable and at least one tenant setting could be read.</summary>
    public bool IsAssessable => ReadError is null &&
        (ConditionalAccessReadable || AuthorizationPolicyReadable || RolesReadable || AuthMethodsReadable || SecurityDefaultsEnabled is not null);
    public string NotReadReason => ReadError ?? "Microsoft Entra ID settings were not read (no Microsoft Graph data).";
}

// ── Identity and Access Management ───────────────────────────────────────────

public sealed class RoleAssignmentInfo
{
    public string Id { get; set; } = string.Empty;
    public string SubscriptionId { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public string RoleDefinitionId { get; set; } = string.Empty;
    public string RoleName { get; set; } = string.Empty;
    public string PrincipalId { get; set; } = string.Empty;
    /// <summary>User, Group, ServicePrincipal (includes managed identities), or "" when unknown.</summary>
    public string PrincipalType { get; set; } = string.Empty;
    public string PrincipalName { get; set; } = string.Empty;
    public bool? IsOrphaned { get; set; }
    public bool? IsGuest { get; set; }

    public string ScopeLevel
    {
        get
        {
            var s = Scope.ToLowerInvariant();
            if (s.StartsWith("/providers/microsoft.management/managementgroups")) return "Management group";
            if (s == "/") return "Root";
            var segs = s.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (segs.Length <= 2) return "Subscription";
            if (segs.Length <= 4) return "Resource group";
            return "Resource";
        }
    }
    public bool IsSubscriptionOrAbove => ScopeLevel is "Subscription" or "Management group" or "Root";
    public bool IsOwner => RoleName.Equals("Owner", StringComparison.OrdinalIgnoreCase);
    public bool IsContributor => RoleName.Equals("Contributor", StringComparison.OrdinalIgnoreCase);
    public bool IsUserAccessAdmin => RoleName.Equals("User Access Administrator", StringComparison.OrdinalIgnoreCase);
    public bool IsPrivileged => IsOwner || IsContributor || IsUserAccessAdmin;
    public bool IsUser => PrincipalType.Equals("User", StringComparison.OrdinalIgnoreCase);
    public bool IsGroup => PrincipalType.Equals("Group", StringComparison.OrdinalIgnoreCase);
    public bool IsServicePrincipal => PrincipalType.Equals("ServicePrincipal", StringComparison.OrdinalIgnoreCase);
    public string Display => string.IsNullOrEmpty(PrincipalName) ? PrincipalId : PrincipalName;
}

public sealed class CustomRoleInfo
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string SubscriptionId { get; set; } = string.Empty;
    public List<string> Actions { get; set; } = new();
    public int AssignableScopeCount { get; set; }
    /// <summary>"*" or a top-level provider wildcard such as "Microsoft.Compute/*" grants far more than any one job needs.</summary>
    public bool HasWildcardActions => Actions.Any(a => a == "*" || a.EndsWith("/*", StringComparison.Ordinal) && a.Count(c => c == '/') <= 1);
}

public sealed class ManagedIdentityInfo : ResourceBase { }

public sealed class IamInfo
{
    public List<RoleAssignmentInfo> RoleAssignments { get; set; } = new();
    public List<CustomRoleInfo> CustomRoles { get; set; } = new();
    public List<ManagedIdentityInfo> UserAssignedIdentities { get; set; } = new();
    public bool PrincipalsResolved { get; set; }
    public int? AppsWithExpiredCredentials { get; set; }
    public int? AppsWithLongLivedCredentials { get; set; }
    public List<string> Warnings { get; set; } = new();
}

// ── The whole estate ─────────────────────────────────────────────────────────

/// <summary>Everything discovered across the scanned subscriptions, plus the assessment built from it.</summary>
public sealed class AuditScanResult
{
    public List<string> SubscriptionIds { get; set; } = new();
    public string TenantId { get; set; } = string.Empty;
    public DateTime CompletedAt { get; set; } = DateTime.Now;
    public List<string> Warnings { get; set; } = new();

    /// <summary>Per-source read failures, shown next to the area they affect.</summary>
    public List<DataIssue> Issues { get; set; } = new();

    /// <summary>Resources dropped after collection because they matched the exclusion patterns (restore tests).</summary>
    public int ExcludedCount { get; set; }
    /// <summary>Human-readable list of the exclusion patterns in force, e.g. "'restore'".</summary>
    public string ExclusionPatterns { get; set; } = string.Empty;

    /// <summary>The areas whose data has been collected and rated; the others are "not audited yet" until requested.</summary>
    public HashSet<AuditArea> AssessedAreas { get; set; } = new(AuditAreaExtensions.All);
    public IEnumerable<AuditArea> PendingAreas => AuditAreaExtensions.All.Where(a => !AssessedAreas.Contains(a));

    public List<VirtualMachineInfo> VirtualMachines { get; set; } = new();
    public List<DiskInfo> Disks { get; set; } = new();
    public List<WebAppInfo> WebApps { get; set; } = new();
    public List<AppServicePlanInfo> AppServicePlans { get; set; } = new();

    public List<VirtualNetworkInfo> VirtualNetworks { get; set; } = new();
    public List<NsgInfo> NetworkSecurityGroups { get; set; } = new();
    public List<PublicIpInfo> PublicIps { get; set; } = new();
    public List<NetworkInterfaceInfo> NetworkInterfaces { get; set; } = new();
    public List<PrivateEndpointInfo> PrivateEndpoints { get; set; } = new();
    public List<NetworkWatcherInfo> NetworkWatchers { get; set; } = new();
    public List<FlowLogInfo> FlowLogs { get; set; } = new();
    public List<PrivateDnsZoneInfo> PrivateDnsZones { get; set; } = new();
    public int BastionCount { get; set; }
    public int FirewallCount { get; set; }

    public List<StorageAccountInfo> StorageAccounts { get; set; } = new();
    public List<KeyVaultInfo> KeyVaults { get; set; } = new();
    public List<SqlServerInfo> SqlServers { get; set; } = new();
    public List<SubscriptionSecurityInfo> SubscriptionSecurity { get; set; } = new();

    public EntraTenantInfo Entra { get; set; } = new();
    public IamInfo Iam { get; set; } = new();

    // Assessment output
    public List<AreaRating> Ratings { get; set; } = new();
    public List<AuditFinding> Findings { get; set; } = new();

    public AreaRating? Rating(AuditArea area) => Ratings.FirstOrDefault(r => r.Area == area);
    public IEnumerable<AuditFinding> FindingsFor(AuditArea area) => Findings.Where(f => f.Area == area);

    public int TotalResources =>
        VirtualMachines.Count + Disks.Count + WebApps.Count + AppServicePlans.Count + VirtualNetworks.Count +
        NetworkSecurityGroups.Count + PublicIps.Count + PrivateEndpoints.Count + StorageAccounts.Count + KeyVaults.Count + SqlServers.Count;

    /// <summary>Overall score: the average of the assessed areas.</summary>
    public int OverallScore
    {
        get
        {
            var assessed = Ratings.Where(r => !r.NotAssessed).ToList();
            return assessed.Count == 0 ? 0 : (int)Math.Round(assessed.Average(r => r.Score));
        }
    }
}
