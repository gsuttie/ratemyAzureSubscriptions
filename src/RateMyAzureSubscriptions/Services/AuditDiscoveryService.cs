using System.Text.Json;
using RateMyAzureSubscriptions.Models;
using RateMyAzureSubscriptions.Services.Azure;
using static RateMyAzureSubscriptions.Services.Azure.Json;

namespace RateMyAzureSubscriptions.Services;

/// <summary>
/// Discovers the estate of the selected subscriptions via Azure Resource Graph, ARM and Microsoft Graph,
/// then hands it to the assessors. Strictly read-only: nothing here ever modifies an Azure resource.
/// Every optional data source (Graph, Defender, per-account storage properties) degrades to a warning
/// rather than failing the scan, so a Reader without Graph permissions still gets a useful result.
/// </summary>
public sealed class AuditDiscoveryService
{
    private const string Arm = AzureApi.ArmBase;
    private readonly IAzureApi _azure;
    private readonly ILogger<AuditDiscoveryService> _logger;
    private readonly ExclusionRules _rules;

    public AuditDiscoveryService(IAzureApi azure, ILogger<AuditDiscoveryService> logger, IConfiguration? configuration = null)
    {
        _azure = azure;
        _logger = logger;
        _rules = ExclusionRules.FromConfiguration(configuration);
    }

    /// <summary>The exclusion rules in force (restore tests are never reviewed).</summary>
    public ExclusionRules Rules => _rules;

    // ── Queries ──────────────────────────────────────────────────────────────

    // One query answers the scope step: resources and resource groups per subscription.
    private string SummaryQuery =>
        $"Resources {_rules.KqlFilter()}| summarize resources = count() by subscriptionId " +
        $"| join kind=fullouter (ResourceContainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups' {RgNameFilter()}| summarize groups = count() by subscriptionId) on subscriptionId " +
        "| project subscriptionId = coalesce(subscriptionId, subscriptionId1), resources, groups";

    private string RgNameFilter() => _rules.Patterns.Count == 0 ? "" :
        "| where " + string.Join(" and ", _rules.Patterns.Select(p => $"name !contains '{p}'")) + " ";

    // Every resource type the audit looks at, fetched in ONE paged Resource Graph query. ARG quota is per user
    // (about 15 queries per 5 seconds), so the number of queries matters far more than the number of rows.
    private static readonly string[] InventoryTypes =
    [
        "microsoft.compute/virtualmachines", "microsoft.compute/disks", "microsoft.web/sites", "microsoft.web/serverfarms",
        "microsoft.network/virtualnetworks", "microsoft.network/networksecuritygroups", "microsoft.network/publicipaddresses",
        "microsoft.network/networkinterfaces", "microsoft.network/privateendpoints", "microsoft.network/networkwatchers",
        "microsoft.network/networkwatchers/flowlogs", "microsoft.network/privatednszones", "microsoft.network/bastionhosts",
        "microsoft.network/azurefirewalls", "microsoft.storage/storageaccounts", "microsoft.keyvault/vaults", "microsoft.sql/servers",
        "microsoft.operationalinsights/workspaces", "microsoft.managedidentity/userassignedidentities",
    ];

    private string InventoryQuery =>
        $"Resources | where type in~ ({string.Join(",", InventoryTypes.Select(t => $"'{t}'"))}) {_rules.KqlFilter()}" +
        "| extend powerState = tostring(properties.extended.instanceView.powerState.code) " +
        "| project id, name, type, location, resourceGroup, subscriptionId, sku, kind, properties, identity, zones, powerState";

    private const string BackupQuery =
        "RecoveryServicesResources | where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems' " +
        "| where properties.backupManagementType =~ 'AzureIaasVM' | project vmId = tolower(tostring(properties.sourceResourceId)), status = tostring(properties.protectionState)";

    private const string SecureScoreQuery =
        "SecurityResources | where type =~ 'microsoft.security/securescores' | where name =~ 'ascScore' " +
        "| project subscriptionId, current = todouble(properties.score.current), max = todouble(properties.score.max), pct = todouble(properties.score.percentage)";

    private const string AssessmentsQuery =
        "SecurityResources | where type =~ 'microsoft.security/assessments' " +
        "| extend status = tostring(properties.status.code), severity = tostring(properties.metadata.severity) " +
        "| summarize cnt = count() by subscriptionId, status, severity";

    private const string PolicyQuery =
        "PolicyResources | where type =~ 'microsoft.authorization/policyassignments' " +
        "| project id, name, subscriptionId, displayName = tostring(properties.displayName), policyDefinitionId = tostring(properties.policyDefinitionId), scope = tostring(properties.scope)";

    private const string CustomRoleQuery =
        "AuthorizationResources | where type =~ 'microsoft.authorization/roledefinitions' | where properties.type =~ 'CustomRole' " +
        "| project id, name, subscriptionId, roleName = tostring(properties.roleName), permissions = properties.permissions, assignableScopes = properties.assignableScopes";

    private const string RoleAssignmentQuery =
        "AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments' " +
        "| project id, subscriptionId, scope = tostring(properties.scope), roleDefinitionId = tostring(properties.roleDefinitionId), principalId = tostring(properties.principalId), principalType = tostring(properties.principalType)";

    private const string RoleDefinitionNamesQuery =
        "AuthorizationResources | where type =~ 'microsoft.authorization/roledefinitions' | project id, roleName = tostring(properties.roleName) | distinct id, roleName";

    // ── Public API ───────────────────────────────────────────────────────────

    public async Task<Dictionary<string, SubscriptionSummary>> GetSummariesAsync(
        IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default)
    {
        var result = subscriptionIds.ToDictionary(id => id, id => new SubscriptionSummary { SubscriptionId = id }, StringComparer.OrdinalIgnoreCase);
        if (subscriptionIds.Count == 0) return result;

        foreach (var row in await _azure.QueryResourceGraphAsync(SummaryQuery, subscriptionIds, tenantId, ct))
        {
            if (!result.TryGetValue(Str(row, "subscriptionId"), out var s)) continue;
            s.ResourceCount += Int(row, "resources") ?? 0;
            s.ResourceGroupCount += Int(row, "groups") ?? 0;
        }
        return result;
    }

    /// <summary>Full read-only scan of the supplied subscriptions (which must share a tenant), all areas.</summary>
    public Task<AuditScanResult> ScanAsync(IReadOnlyCollection<string> subscriptionIds, string? tenantId,
        IProgress<string>? progress = null, CancellationToken ct = default) =>
        ScanAsync(subscriptionIds, tenantId, AuditAreaExtensions.All, progress, ct);

    /// <summary>
    /// Read-only scan of the supplied subscriptions for the requested areas. The inventory (one Resource Graph
    /// query) is always read because areas share it; the per-area extras (backup state, Defender, role
    /// assignments, Microsoft Graph, per-account storage properties) are only read for the requested areas.
    /// </summary>
    public async Task<AuditScanResult> ScanAsync(IReadOnlyCollection<string> subscriptionIds, string? tenantId,
        IReadOnlyCollection<AuditArea> areas, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var result = new AuditScanResult { SubscriptionIds = subscriptionIds.ToList(), TenantId = tenantId ?? "", AssessedAreas = new HashSet<AuditArea>(areas) };
        if (subscriptionIds.Count == 0) return result;
        var wanted = result.AssessedAreas;

        if (wanted.Any(a => a != AuditArea.EntraId))
        {
            progress?.Report("Reading the resource inventory (Azure Resource Graph)…");
            var rows = await _azure.QueryResourceGraphAsync(InventoryQuery, subscriptionIds, tenantId, ct);
            DispatchInventory(result, rows);
        }

        if (wanted.Contains(AuditArea.Compute))
        {
            progress?.Report("Reading backup protection…");
            await CollectBackupAsync(result, subscriptionIds, tenantId, ct);
        }
        if (wanted.Contains(AuditArea.Storage))
        {
            progress?.Report("Reading storage account properties…");
            await CollectStoragePropertiesAsync(result, tenantId, ct);
        }
        if (wanted.Contains(AuditArea.Security))
        {
            progress?.Report("Reading Defender for Cloud, policy and logging…");
            await CollectSecurityAsync(result, subscriptionIds, tenantId, ct);
        }
        if (wanted.Contains(AuditArea.Iam))
        {
            progress?.Report("Reading role assignments…");
            await CollectIamAsync(result, subscriptionIds, tenantId, ct);
        }
        if (wanted.Contains(AuditArea.EntraId))
        {
            progress?.Report("Reading Microsoft Entra ID (Microsoft Graph)…");
            await CollectEntraAsync(result, tenantId, ct);
        }

        progress?.Report("Rating…");
        Finalize(result, _rules);
        return result;
    }

    /// <summary>Routes the rows of the combined inventory query into the typed lists.</summary>
    internal static void DispatchInventory(AuditScanResult r, IEnumerable<JsonElement> rows)
    {
        var lawCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            switch (Str(row, "type").ToLowerInvariant())
            {
                case "microsoft.compute/virtualmachines": r.VirtualMachines.Add(ParseVm(row)); break;
                case "microsoft.compute/disks": r.Disks.Add(ParseDisk(row)); break;
                case "microsoft.web/sites": r.WebApps.Add(ParseWebApp(row)); break;
                case "microsoft.web/serverfarms": r.AppServicePlans.Add(ParsePlan(row)); break;
                case "microsoft.network/virtualnetworks": r.VirtualNetworks.Add(ParseVNet(row)); break;
                case "microsoft.network/networksecuritygroups": r.NetworkSecurityGroups.Add(ParseNsg(row)); break;
                case "microsoft.network/publicipaddresses": r.PublicIps.Add(ParsePublicIp(row)); break;
                case "microsoft.network/networkinterfaces": r.NetworkInterfaces.Add(ParseNic(row)); break;
                case "microsoft.network/privateendpoints": r.PrivateEndpoints.Add(ParsePrivateEndpoint(row)); break;
                case "microsoft.network/networkwatchers": r.NetworkWatchers.Add(Base<NetworkWatcherInfo>(row)); break;
                case "microsoft.network/networkwatchers/flowlogs": r.FlowLogs.Add(ParseFlowLog(row)); break;
                case "microsoft.network/privatednszones": r.PrivateDnsZones.Add(Base<PrivateDnsZoneInfo>(row)); break;
                case "microsoft.network/bastionhosts": r.BastionCount++; break;
                case "microsoft.network/azurefirewalls": r.FirewallCount++; break;
                case "microsoft.storage/storageaccounts": r.StorageAccounts.Add(ParseStorageAccount(row)); break;
                case "microsoft.keyvault/vaults": r.KeyVaults.Add(ParseKeyVault(row)); break;
                case "microsoft.sql/servers": r.SqlServers.Add(ParseSqlServer(row)); break;
                case "microsoft.operationalinsights/workspaces": lawCounts[Str(row, "subscriptionId")] = lawCounts.GetValueOrDefault(Str(row, "subscriptionId")) + 1; break;
                case "microsoft.managedidentity/userassignedidentities": r.Iam.UserAssignedIdentities.Add(Base<ManagedIdentityInfo>(row)); break;
            }
        }
        foreach (var sub in r.SubscriptionIds)
            r.SubscriptionSecurity.Add(new SubscriptionSecurityInfo { SubscriptionId = sub, LogAnalyticsWorkspaceCount = lawCounts.GetValueOrDefault(sub) });
    }

    /// <summary>Links cross-area facts (public IPs on VMs, private endpoints on storage) and runs the assessors.</summary>
    public static void Finalize(AuditScanResult result) => Finalize(result, null);

    /// <summary>Applies the exclusion rules, links cross-area facts and runs the assessors.</summary>
    public static void Finalize(AuditScanResult result, ExclusionRules? rules)
    {
        rules ??= ExclusionRules.Default;
        rules.Apply(result);
        result.ExclusionPatterns = rules.Description;

        var pipByNic = result.NetworkInterfaces.Where(n => n.PublicIpIds.Count > 0).Select(n => n.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var vm in result.VirtualMachines)
            if (vm.NicIds.Any(pipByNic.Contains)) vm.HasPublicIp = true;

        var peTargets = result.PrivateEndpoints.Where(p => p.TargetResourceId is not null).Select(p => p.TargetResourceId!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var sa in result.StorageAccounts)
            if (peTargets.Contains(sa.Id)) sa.HasPrivateEndpoint = true;

        result.CompletedAt = DateTime.Now;
        AuditRatingService.AssessAll(result);
    }

    // ── Compute ──────────────────────────────────────────────────────────────

    private async Task CollectBackupAsync(AuditScanResult r, IReadOnlyCollection<string> subs, string? tenantId, CancellationToken ct)
    {
        if (r.VirtualMachines.Count == 0) return;
        try
        {
            var backup = await _azure.QueryResourceGraphAsync(BackupQuery, subs, tenantId, ct);
            var protectedIds = backup.Select(b => Str(b, "vmId")).Where(v => !string.IsNullOrEmpty(v)).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var vm in r.VirtualMachines) vm.IsBackedUp = protectedIds.Contains(vm.Id);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Issue(r, AuditArea.Compute, "Azure Backup protection state", ReaderNeeds, "Backup rated as unknown (half points).", ex);
        }
    }

    internal static VirtualMachineInfo ParseVm(JsonElement row)
    {
        var p = Obj(row, "properties");
        var vm = Base<VirtualMachineInfo>(row);
        vm.Size = Str(Obj(p, "hardwareProfile"), "vmSize");
        vm.OsType = Str(Obj(Obj(p, "storageProfile"), "osDisk"), "osType");
        if (string.IsNullOrEmpty(vm.OsType)) vm.OsType = Obj(Obj(p, "osProfile"), "windowsConfiguration").ValueKind == JsonValueKind.Object ? "Windows" : Obj(Obj(p, "osProfile"), "linuxConfiguration").ValueKind == JsonValueKind.Object ? "Linux" : "";
        var ps = Str(row, "powerState");
        vm.PowerState = ps.StartsWith("PowerState/", StringComparison.OrdinalIgnoreCase) ? ps["PowerState/".Length..] : ps;
        vm.Zones = Arr(row, "zones").Select(z => z.ToString()).ToList();
        vm.AvailabilitySetId = NullIfEmpty(Str(Obj(p, "availabilitySet"), "id"));
        vm.UsesManagedDisks = Obj(Obj(Obj(p, "storageProfile"), "osDisk"), "managedDisk").ValueKind == JsonValueKind.Object;
        vm.BootDiagnosticsEnabled = Bool(Obj(Obj(p, "diagnosticsProfile"), "bootDiagnostics"), "enabled") == true;
        vm.HasManagedIdentity = HasIdentity(row);
        vm.LicenseType = Str(p, "licenseType");
        vm.NicIds = Arr(Obj(p, "networkProfile"), "networkInterfaces").Select(n => Str(n, "id")).Where(i => !string.IsNullOrEmpty(i)).ToList();
        return vm;
    }

    internal static DiskInfo ParseDisk(JsonElement row)
    {
        var p = Obj(row, "properties");
        var d = Base<DiskInfo>(row);
        d.SizeGb = Int(p, "diskSizeGB") ?? 0;
        d.Sku = Str(Obj(row, "sku"), "name");
        d.DiskState = Str(p, "diskState");
        return d;
    }

    internal static WebAppInfo ParseWebApp(JsonElement row)
    {
        var p = Obj(row, "properties");
        var cfg = Obj(p, "siteConfig");
        var a = Base<WebAppInfo>(row);
        a.Kind = Str(row, "kind");
        a.State = Str(p, "state");
        a.HttpsOnly = Bool(p, "httpsOnly") == true;
        a.MinTlsVersion = Str(cfg, "minTlsVersion");
        a.FtpsState = Str(cfg, "ftpsState");
        a.AlwaysOn = Bool(cfg, "alwaysOn");
        a.HasManagedIdentity = HasIdentity(row);
        a.ServerFarmId = NullIfEmpty(Str(p, "serverFarmId"));
        a.PublicNetworkAccess = Str(p, "publicNetworkAccess");
        return a;
    }

    internal static AppServicePlanInfo ParsePlan(JsonElement row)
    {
        var p = Obj(row, "properties");
        var sku = Obj(row, "sku");
        var plan = Base<AppServicePlanInfo>(row);
        plan.SkuTier = Str(sku, "tier");
        plan.SkuName = Str(sku, "name");
        plan.Capacity = Int(sku, "capacity") ?? 1;
        plan.NumberOfSites = Int(p, "numberOfSites") ?? 0;
        plan.ZoneRedundant = Bool(p, "zoneRedundant") == true;
        return plan;
    }

    // ── Networking ───────────────────────────────────────────────────────────

    internal static VirtualNetworkInfo ParseVNet(JsonElement row)
    {
        var p = Obj(row, "properties");
        var v = Base<VirtualNetworkInfo>(row);
        v.AddressSpaces = Arr(Obj(p, "addressSpace"), "addressPrefixes").Select(a => a.ToString()).ToList();
        v.DdosProtectionEnabled = Bool(p, "enableDdosProtection") == true;
        v.PeeringCount = ArrLen(p, "virtualNetworkPeerings");
        foreach (var s in Arr(p, "subnets"))
        {
            var sp = Obj(s, "properties");
            v.Subnets.Add(new SubnetInfo
            {
                Id = Str(s, "id"),
                Name = Str(s, "name"),
                AddressPrefix = FirstNonEmpty(Str(sp, "addressPrefix"), string.Join(",", Arr(sp, "addressPrefixes").Select(a => a.ToString()))),
                NsgId = NullIfEmpty(Str(Obj(sp, "networkSecurityGroup"), "id")),
                RouteTableId = NullIfEmpty(Str(Obj(sp, "routeTable"), "id")),
                HasDelegation = ArrLen(sp, "delegations") > 0,
            });
        }
        return v;
    }

    internal static NsgInfo ParseNsg(JsonElement row)
    {
        var p = Obj(row, "properties");
        var n = Base<NsgInfo>(row);
        n.SubnetCount = ArrLen(p, "subnets");
        n.NicCount = ArrLen(p, "networkInterfaces");
        foreach (var rule in Arr(p, "securityRules"))
        {
            var rp = Obj(rule, "properties");
            var sources = Arr(rp, "sourceAddressPrefixes").Select(a => a.ToString()).ToList();
            var single = Str(rp, "sourceAddressPrefix");
            if (!string.IsNullOrEmpty(single)) sources.Add(single);
            var ports = Arr(rp, "destinationPortRanges").Select(a => a.ToString()).ToList();
            var singlePort = Str(rp, "destinationPortRange");
            if (!string.IsNullOrEmpty(singlePort)) ports.Add(singlePort);
            n.Rules.Add(new NsgRuleInfo
            {
                Name = Str(rule, "name"),
                Priority = Int(rp, "priority") ?? 0,
                Direction = Str(rp, "direction"),
                Access = Str(rp, "access"),
                Protocol = Str(rp, "protocol"),
                Sources = sources,
                DestinationPorts = ports,
            });
        }
        return n;
    }

    internal static PublicIpInfo ParsePublicIp(JsonElement row)
    {
        var p = Obj(row, "properties");
        var ip = Base<PublicIpInfo>(row);
        ip.IpAddress = Str(p, "ipAddress");
        ip.Sku = Str(Obj(row, "sku"), "name");
        ip.AttachedToId = NullIfEmpty(FirstNonEmpty(Str(Obj(p, "ipConfiguration"), "id"), Str(Obj(p, "natGateway"), "id")));
        return ip;
    }

    internal static NetworkInterfaceInfo ParseNic(JsonElement row)
    {
        var p = Obj(row, "properties");
        var nic = Base<NetworkInterfaceInfo>(row);
        nic.VirtualMachineId = NullIfEmpty(Str(Obj(p, "virtualMachine"), "id"));
        nic.PublicIpIds = Arr(p, "ipConfigurations").Select(c => Str(Obj(Obj(c, "properties"), "publicIPAddress"), "id")).Where(i => !string.IsNullOrEmpty(i)).ToList();
        return nic;
    }

    internal static PrivateEndpointInfo ParsePrivateEndpoint(JsonElement row)
    {
        var p = Obj(row, "properties");
        var pe = Base<PrivateEndpointInfo>(row);
        var conn = Arr(p, "privateLinkServiceConnections").Concat(Arr(p, "manualPrivateLinkServiceConnections")).FirstOrDefault();
        var cp = Obj(conn, "properties");
        pe.TargetResourceId = NullIfEmpty(Str(cp, "privateLinkServiceId"));
        pe.GroupId = Arr(cp, "groupIds").Select(g => g.ToString()).FirstOrDefault() ?? "";
        return pe;
    }

    internal static FlowLogInfo ParseFlowLog(JsonElement row)
    {
        var p = Obj(row, "properties");
        var f = Base<FlowLogInfo>(row);
        f.TargetResourceId = Str(p, "targetResourceId");
        f.Enabled = Bool(p, "enabled") == true;
        return f;
    }

    // ── Storage ──────────────────────────────────────────────────────────────

    private const int MaxPerAccountReads = 60;
    private Exception? _lastStorageError;

    private async Task CollectStoragePropertiesAsync(AuditScanResult r, string? tenantId, CancellationToken ct)
    {
        // Blob service properties and lifecycle policies are not in Resource Graph; read them per account, capped.
        var toRead = r.StorageAccounts.Take(MaxPerAccountReads).ToList();
        if (r.StorageAccounts.Count > MaxPerAccountReads)
            r.Warnings.Add($"Soft delete, versioning and lifecycle policies were read for the first {MaxPerAccountReads} of {r.StorageAccounts.Count} storage accounts.");

        var failures = 0;
        await Parallel.ForEachAsync(toRead, new ParallelOptions { MaxDegreeOfParallelism = 6, CancellationToken = ct }, async (sa, token) =>
        {
            try
            {
                var blob = await _azure.GetArmAsync($"{Arm}{sa.Id}/blobServices/default?api-version=2023-05-01", tenantId, token);
                if (blob is { } b) ApplyBlobServiceProperties(sa, b);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Interlocked.Increment(ref failures);
                _lastStorageError = ex;
                _logger.LogDebug("Blob service properties unavailable for {Account}: {Message}", sa.Name, ex.Message);
            }
            try
            {
                var policy = await _azure.GetArmAsync($"{Arm}{sa.Id}/managementPolicies/default?api-version=2023-05-01", tenantId, token);
                sa.HasLifecyclePolicy = policy is { } p && ArrLen(Obj(Obj(p, "properties"), "policy"), "rules") > 0;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "Lifecycle policy unavailable for {Account}", sa.Name);
            }
        });
        if (failures > 0)
            r.Issues.Add(new DataIssue { Area = AuditArea.Storage, Source = $"Blob service properties ({failures} of {toRead.Count} accounts)", Reason = Describe(_lastStorageError), Needs = ReaderNeeds, Impact = "Soft delete and versioning rated as unknown for those accounts.", Detail = Short(_lastStorageError?.Message ?? "") });
    }

    internal static StorageAccountInfo ParseStorageAccount(JsonElement row)
    {
        var p = Obj(row, "properties");
        var enc = Obj(p, "encryption");
        var sa = Base<StorageAccountInfo>(row);
        sa.Kind = Str(row, "kind");
        sa.SkuName = Str(Obj(row, "sku"), "name");
        sa.AccessTier = Str(p, "accessTier");
        sa.AllowBlobPublicAccess = Bool(p, "allowBlobPublicAccess");
        sa.SupportsHttpsTrafficOnly = Bool(p, "supportsHttpsTrafficOnly") != false;
        sa.MinimumTlsVersion = Str(p, "minimumTlsVersion");
        sa.AllowSharedKeyAccess = Bool(p, "allowSharedKeyAccess");
        sa.PublicNetworkAccess = Str(p, "publicNetworkAccess");
        sa.NetworkDefaultAction = Str(Obj(p, "networkAcls"), "defaultAction");
        sa.InfrastructureEncryption = Bool(enc, "requireInfrastructureEncryption") == true;
        sa.AllowCrossTenantReplication = Bool(p, "allowCrossTenantReplication");
        sa.DefaultToOAuthAuthentication = Bool(p, "defaultToOAuthAuthentication");
        sa.IsHierarchicalNamespace = Bool(p, "isHnsEnabled") == true;
        sa.HasPrivateEndpoint = ArrLen(p, "privateEndpointConnections") > 0;
        return sa;
    }

    internal static void ApplyBlobServiceProperties(StorageAccountInfo sa, JsonElement blobService)
    {
        var p = Obj(blobService, "properties");
        var del = Obj(p, "deleteRetentionPolicy");
        sa.BlobSoftDeleteEnabled = Bool(del, "enabled") == true;
        sa.BlobSoftDeleteDays = Int(del, "days");
        sa.ContainerSoftDeleteEnabled = Bool(Obj(p, "containerDeleteRetentionPolicy"), "enabled") == true;
        sa.VersioningEnabled = Bool(p, "isVersioningEnabled") == true;
    }

    // ── Security ─────────────────────────────────────────────────────────────

    private async Task CollectSecurityAsync(AuditScanResult r, IReadOnlyCollection<string> subs, string? tenantId, CancellationToken ct)
    {
        // Key Vaults, SQL servers and workspace counts come from the inventory query; only the Defender,
        // policy and diagnostic-settings sources are read here (three ARG queries + a few ARM GETs per subscription).
        await TryAsync(r, AuditArea.Security, "Secure score", ReaderNeeds + " and Defender for Cloud enabled", "Secure score rated as unknown (2 of 5 points).", async () =>
        {
            foreach (var row in await _azure.QueryResourceGraphAsync(SecureScoreQuery, subs, tenantId, ct))
            {
                var s = r.SubscriptionSecurity.FirstOrDefault(x => x.SubscriptionId.Equals(Str(row, "subscriptionId"), StringComparison.OrdinalIgnoreCase));
                if (s is null) continue;
                if (row.TryGetProperty("pct", out var pct) && pct.ValueKind == JsonValueKind.Number) s.SecureScorePercent = pct.GetDouble() * (pct.GetDouble() <= 1 ? 100 : 1);
            }
        });

        await TryAsync(r, AuditArea.Security, "Defender for Cloud recommendations", ReaderNeeds + " and Defender for Cloud enabled", "Security posture rated as unknown (half points).", async () =>
        {
            foreach (var row in await _azure.QueryResourceGraphAsync(AssessmentsQuery, subs, tenantId, ct))
            {
                var s = r.SubscriptionSecurity.FirstOrDefault(x => x.SubscriptionId.Equals(Str(row, "subscriptionId"), StringComparison.OrdinalIgnoreCase));
                if (s is null) continue;
                var cnt = Int(row, "cnt") ?? 0;
                var status = Str(row, "status");
                if (status.Equals("Healthy", StringComparison.OrdinalIgnoreCase)) s.HealthyAssessments += cnt;
                else if (status.Equals("Unhealthy", StringComparison.OrdinalIgnoreCase))
                {
                    s.UnhealthyAssessments += cnt;
                    if (Str(row, "severity").Equals("High", StringComparison.OrdinalIgnoreCase)) s.HighSeverityUnhealthy += cnt;
                }
            }
        });

        await TryAsync(r, AuditArea.Security, "Azure Policy assignments", ReaderNeeds, "Policy counted as none assigned.", async () =>
        {
            foreach (var row in await _azure.QueryResourceGraphAsync(PolicyQuery, subs, tenantId, ct))
            {
                var s = r.SubscriptionSecurity.FirstOrDefault(x => x.SubscriptionId.Equals(Str(row, "subscriptionId"), StringComparison.OrdinalIgnoreCase));
                if (s is null) continue;
                s.PolicyAssignmentCount++;
                var name = FirstNonEmpty(Str(row, "displayName"), Str(row, "name"));
                s.PolicyAssignmentNames.Add(name);
                var def = Str(row, "policyDefinitionId");
                if (def.Contains("1f3afdf9-d0c9-4c3d-847f-89da613e70a8", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("security benchmark", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Azure Security Benchmark", StringComparison.OrdinalIgnoreCase))
                    s.HasSecurityBenchmarkAssignment = true;
            }
        });

        foreach (var s in r.SubscriptionSecurity)
        {
            await TryAsync(r, AuditArea.Security, $"Defender for Cloud plans ({s.SubscriptionId})", "Reader or Security Reader on the subscription", "Defender plans rated as unknown (half points).", async () =>
            {
                foreach (var row in await _azure.GetArmListAsync($"{Arm}/subscriptions/{s.SubscriptionId}/providers/Microsoft.Security/pricings?api-version=2024-01-01", tenantId, ct))
                    s.DefenderPlans[Str(row, "name")] = Str(Obj(row, "properties"), "pricingTier");
            });
            await TryAsync(r, AuditArea.Security, $"Defender security contact ({s.SubscriptionId})", "Reader or Security Reader on the subscription", "Security contact not scored for this subscription.", async () =>
            {
                var contacts = await _azure.GetArmListAsync($"{Arm}/subscriptions/{s.SubscriptionId}/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview", tenantId, ct);
                s.SecurityContactConfigured = contacts.Any(c => !string.IsNullOrEmpty(Str(Obj(c, "properties"), "emails")) || ArrLen(Obj(Obj(c, "properties"), "notificationsByRole"), "roles") > 0);
            });
            await TryAsync(r, AuditArea.Security, $"Activity Log diagnostic settings ({s.SubscriptionId})", ReaderNeeds, "Activity Log export rated as unknown (half points).", async () =>
            {
                var settings = await _azure.GetArmListAsync($"{Arm}/subscriptions/{s.SubscriptionId}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview", tenantId, ct);
                var dests = new List<string>();
                foreach (var ds in settings)
                {
                    var p = Obj(ds, "properties");
                    if (!Arr(p, "logs").Any(l => Bool(l, "enabled") == true)) continue;
                    if (!string.IsNullOrEmpty(Str(p, "workspaceId"))) dests.Add("Log Analytics: " + LastSegment(Str(p, "workspaceId")));
                    if (!string.IsNullOrEmpty(Str(p, "storageAccountId"))) dests.Add("Storage: " + LastSegment(Str(p, "storageAccountId")));
                    if (!string.IsNullOrEmpty(Str(p, "eventHubAuthorizationRuleId"))) dests.Add("Event Hub");
                }
                s.ActivityLogDestinations = dests;
                s.ActivityLogExported = dests.Count > 0;
            });
        }
    }

    internal static KeyVaultInfo ParseKeyVault(JsonElement row)
    {
        var p = Obj(row, "properties");
        var kv = Base<KeyVaultInfo>(row);
        kv.SoftDeleteEnabled = Bool(p, "enableSoftDelete") != false;
        kv.PurgeProtectionEnabled = Bool(p, "enablePurgeProtection") == true;
        kv.RbacAuthorization = Bool(p, "enableRbacAuthorization") == true;
        kv.PublicNetworkAccess = Str(p, "publicNetworkAccess");
        kv.NetworkDefaultAction = Str(Obj(p, "networkAcls"), "defaultAction");
        return kv;
    }

    internal static SqlServerInfo ParseSqlServer(JsonElement row)
    {
        var p = Obj(row, "properties");
        var q = Base<SqlServerInfo>(row);
        q.MinimalTlsVersion = Str(p, "minimalTlsVersion");
        q.PublicNetworkAccess = Str(p, "publicNetworkAccess");
        var admins = Obj(p, "administrators");
        q.EntraOnlyAuthentication = Bool(admins, "azureADOnlyAuthentication") == true;
        q.HasEntraAdmin = !string.IsNullOrEmpty(Str(admins, "login")) || !string.IsNullOrEmpty(Str(admins, "sid"));
        return q;
    }

    // ── IAM ──────────────────────────────────────────────────────────────────

    private async Task CollectIamAsync(AuditScanResult r, IReadOnlyCollection<string> subs, string? tenantId, CancellationToken ct)
    {
        var iam = r.Iam;
        await TryAsync(r, AuditArea.Iam, "Role assignments and definitions", ReaderNeeds, "IAM cannot be rated without role assignments.", async () =>
        {
            // Sequential on purpose: ARG quota is shared, so parallel queries gain nothing and risk throttling.
            var raRows = await _azure.QueryResourceGraphAsync(RoleAssignmentQuery, subs, tenantId, ct);
            var nameRows = await _azure.QueryResourceGraphAsync(RoleDefinitionNamesQuery, subs, tenantId, ct);
            var customRows = await _azure.QueryResourceGraphAsync(CustomRoleQuery, subs, tenantId, ct);

            var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var row in nameRows)
                names[LastSegment(Str(row, "id"))] = Str(row, "roleName");
            foreach (var row in raRows)
            {
                var ra = ParseRoleAssignment(row);
                ra.RoleName = names.TryGetValue(LastSegment(ra.RoleDefinitionId), out var n) ? n : BuiltInRoleName(ra.RoleDefinitionId);
                iam.RoleAssignments.Add(ra);
            }
            iam.RoleAssignments = iam.RoleAssignments.DistinctBy(a => a.Id, StringComparer.OrdinalIgnoreCase).ToList();
            iam.CustomRoles.AddRange(customRows.Select(ParseCustomRole).DistinctBy(c => c.Id, StringComparer.OrdinalIgnoreCase));
        });

        // Resolve principals through Microsoft Graph (best effort).
        var ids = iam.RoleAssignments.Select(a => a.PrincipalId).Where(p => !string.IsNullOrEmpty(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (ids.Count > 0)
        {
            try
            {
                var found = new Dictionary<string, (string Name, string Type, bool Guest)>(StringComparer.OrdinalIgnoreCase);
                foreach (var chunk in ids.Chunk(900))
                {
                    var body = JsonSerializer.Serialize(new { ids = chunk, types = new[] { "user", "group", "servicePrincipal" } });
                    foreach (var o in await _azure.PostGraphAsync("v1.0/directoryObjects/getByIds", body, tenantId, ct))
                    {
                        var type = Str(o, "@odata.type").Replace("#microsoft.graph.", "");
                        found[Str(o, "id")] = (FirstNonEmpty(Str(o, "displayName"), Str(o, "userPrincipalName")), type, Str(o, "userType").Equals("Guest", StringComparison.OrdinalIgnoreCase));
                    }
                }
                foreach (var a in iam.RoleAssignments)
                {
                    if (found.TryGetValue(a.PrincipalId, out var f))
                    {
                        a.PrincipalName = f.Name;
                        a.IsOrphaned = false;
                        a.IsGuest = f.Guest;
                        if (string.IsNullOrEmpty(a.PrincipalType))
                            a.PrincipalType = f.Type.Equals("user", StringComparison.OrdinalIgnoreCase) ? "User" : f.Type.Equals("group", StringComparison.OrdinalIgnoreCase) ? "Group" : "ServicePrincipal";
                    }
                    else
                    {
                        a.IsOrphaned = true;
                        a.IsGuest = false;
                    }
                }
                iam.PrincipalsResolved = true;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Issue(r, AuditArea.Iam, "Principal names (Microsoft Graph directoryObjects/getByIds)", "Microsoft Graph Directory.Read.All (Directory Readers role)", "Principal names not shown; orphaned and guest assignments rated as unknown (half points).", ex);
            }
        }

        try
        {
            var apps = await _azure.GetGraphListAsync("v1.0/applications?$select=id,displayName,passwordCredentials,keyCredentials&$top=999", tenantId, ct);
            var now = DateTimeOffset.UtcNow;
            int expired = 0, longLived = 0;
            foreach (var app in apps)
            {
                var creds = Arr(app, "passwordCredentials").Concat(Arr(app, "keyCredentials")).ToList();
                if (creds.Any(c => DateTimeOffset.TryParse(Str(c, "endDateTime"), out var end) && end < now)) expired++;
                if (Arr(app, "passwordCredentials").Any(c => DateTimeOffset.TryParse(Str(c, "startDateTime"), out var start) && DateTimeOffset.TryParse(Str(c, "endDateTime"), out var end) && end > now && (end - start).TotalDays > 730)) longLived++;
            }
            iam.AppsWithExpiredCredentials = expired;
            iam.AppsWithLongLivedCredentials = longLived;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Issue(r, AuditArea.Iam, "App registration credentials (Microsoft Graph applications)", "Microsoft Graph Application.Read.All (Application Administrator or Global Reader)", "Credential hygiene rated as unknown (half points).", ex);
        }
    }

    internal static RoleAssignmentInfo ParseRoleAssignment(JsonElement row) => new()
    {
        Id = Str(row, "id"),
        SubscriptionId = Str(row, "subscriptionId"),
        Scope = Str(row, "scope"),
        RoleDefinitionId = Str(row, "roleDefinitionId"),
        PrincipalId = Str(row, "principalId"),
        PrincipalType = Str(row, "principalType"),
    };

    internal static CustomRoleInfo ParseCustomRole(JsonElement row) => new()
    {
        Id = Str(row, "id"),
        Name = FirstNonEmpty(Str(row, "roleName"), Str(row, "name")),
        SubscriptionId = Str(row, "subscriptionId"),
        Actions = Arr(row, "permissions").SelectMany(p => Arr(p, "actions")).Select(a => a.ToString()).ToList(),
        AssignableScopeCount = ArrLen(row, "assignableScopes"),
    };

    internal static string BuiltInRoleName(string roleDefinitionId) => LastSegment(roleDefinitionId).ToLowerInvariant() switch
    {
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" => "Owner",
        "b24988ac-6180-42a0-ab88-20f7382dd24c" => "Contributor",
        "acdd72a7-3385-48ef-bd42-f606fba81ae7" => "Reader",
        "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" => "User Access Administrator",
        _ => LastSegment(roleDefinitionId),
    };

    // ── Microsoft Entra ID ───────────────────────────────────────────────────

    private const string GlobalAdminTemplate = "62e90394-69f5-4237-9190-012177145e10";
    private static readonly string[] PrivilegedTemplates =
    [
        GlobalAdminTemplate,
        "e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", // Application Administrator
        "fe930be7-5e62-47db-91af-98c3a49a38b1", // User Administrator
        "29232cdf-9323-42fd-ade2-1d097af3e4de", // Exchange Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", // SharePoint Administrator
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", // Privileged Authentication Administrator
        "c4e39bd9-1100-46d3-8c65-fb160da0071f", // Authentication Administrator
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", // Conditional Access Administrator
    ];

    private async Task CollectEntraAsync(AuditScanResult r, string? tenantId, CancellationToken ct)
    {
        var t = r.Entra;
        t.TenantId = tenantId ?? "";
        try
        {
            var org = (await _azure.GetGraphListAsync("v1.0/organization?$select=id,displayName,verifiedDomains", tenantId, ct)).FirstOrDefault();
            t.DisplayName = Str(org, "displayName");
            t.DefaultDomain = Arr(org, "verifiedDomains").Where(d => Bool(d, "isDefault") == true).Select(d => Str(d, "name")).FirstOrDefault() ?? "";
            if (string.IsNullOrEmpty(t.TenantId)) t.TenantId = Str(org, "id");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            t.ReadError = $"Microsoft Graph could not be read: {Describe(ex)}. Sign in with an account that has Global Reader (or Directory Readers + Security Reader), or grant the identity Microsoft Graph permissions, to rate Microsoft Entra ID.";
            Issue(r, AuditArea.EntraId, "Microsoft Graph (organization)", "Microsoft Graph Directory.Read.All (Global Reader)", "Microsoft Entra ID not assessed.", ex);
            return;
        }

        await TryAsync(r, AuditArea.EntraId, "Security defaults policy", "Microsoft Graph Policy.Read.All (Global Reader)", "Security defaults treated as off; MFA judged on Conditional Access only.", async () =>
        {
            var sd = await _azure.GetGraphAsync("v1.0/policies/identitySecurityDefaultsEnforcementPolicy", tenantId, ct);
            t.SecurityDefaultsEnabled = sd is { } s ? Bool(s, "isEnabled") : null;
        });

        await TryAsync(r, AuditArea.EntraId, "Conditional Access policies", "Microsoft Graph Policy.Read.ConditionalAccess (Global Reader or Security Reader)", "Conditional Access, MFA, risk and device checks rated as unknown (half points).", async () =>
        {
            foreach (var p in await _azure.GetGraphListAsync("v1.0/identity/conditionalAccess/policies", tenantId, ct))
                t.ConditionalAccessPolicies.Add(ParseCaPolicy(p));
            t.ConditionalAccessReadable = true;
        });

        await TryAsync(r, AuditArea.EntraId, "Authorization policy (guest and user settings)", "Microsoft Graph Policy.Read.All (Global Reader)", "External collaboration and user settings rated as unknown (half points).", async () =>
        {
            var ap = await _azure.GetGraphAsync("v1.0/policies/authorizationPolicy", tenantId, ct);
            if (ap is not { } a) return;
            t.AllowInvitesFrom = Str(a, "allowInvitesFrom");
            t.GuestUserRoleId = Str(a, "guestUserRoleId");
            var perms = Obj(a, "defaultUserRolePermissions");
            t.UsersCanRegisterApps = Bool(perms, "allowedToCreateApps");
            t.UsersCanCreateTenants = Bool(perms, "allowedToCreateTenants");
            t.UsersCanCreateSecurityGroups = Bool(perms, "allowedToCreateSecurityGroups");
            var grantPolicies = Arr(perms, "permissionGrantPoliciesAssigned").Select(x => x.ToString()).ToList();
            t.UserConsentAllowed = grantPolicies.Any(g => g.Contains("microsoft-user-default-legacy", StringComparison.OrdinalIgnoreCase));
            t.AuthorizationPolicyReadable = true;
        });

        await TryAsync(r, AuditArea.EntraId, "Directory role members", "Microsoft Graph RoleManagement.Read.Directory and Directory.Read.All (Global Reader)", "Privileged access rated as unknown (half points).", async () =>
        {
            var roles = await _azure.GetGraphListAsync("v1.0/directoryRoles?$select=id,displayName,roleTemplateId", tenantId, ct);
            var privilegedMembers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var role in roles)
            {
                var template = Str(role, "roleTemplateId");
                if (!PrivilegedTemplates.Contains(template, StringComparer.OrdinalIgnoreCase)) continue;
                var members = await _azure.GetGraphListAsync($"v1.0/directoryRoles/{Str(role, "id")}/members?$select=id,displayName,userPrincipalName,userType", tenantId, ct);
                foreach (var m in members)
                {
                    var id = Str(m, "id");
                    if (privilegedMembers.Add(id) && Str(m, "userType").Equals("Guest", StringComparison.OrdinalIgnoreCase)) t.GuestsInPrivilegedRoles++;
                    if (template.Equals(GlobalAdminTemplate, StringComparison.OrdinalIgnoreCase))
                    {
                        t.GlobalAdminCount++;
                        t.GlobalAdminNames.Add(FirstNonEmpty(Str(m, "displayName"), Str(m, "userPrincipalName"), id));
                    }
                }
            }
            t.PrivilegedRoleMemberCount = privilegedMembers.Count;
            t.RolesReadable = true;
        });

        await TryAsync(r, AuditArea.EntraId, "User and guest counts", "Microsoft Graph User.Read.All (Directory Readers)", "Counts not shown; no effect on the score.", async () =>
        {
            var all = await _azure.GetGraphListAsync("v1.0/users/$count", tenantId, ct, consistencyLevelEventual: true);
            var guests = await _azure.GetGraphListAsync("v1.0/users/$count?$filter=userType eq 'Guest'", tenantId, ct, consistencyLevelEventual: true);
            t.UserCount = CountValue(all);
            t.GuestCount = CountValue(guests);
        });

        await TryAsync(r, AuditArea.EntraId, "Authentication methods policy", "Microsoft Graph Policy.Read.All or Policy.ReadWrite.AuthenticationMethod (Global Reader)", "Authentication methods rated as unknown (2 of 4 points).", async () =>
        {
            var policy = await _azure.GetGraphAsync("v1.0/policies/authenticationMethodsPolicy", tenantId, ct);
            if (policy is not { } p) return;
            foreach (var m in Arr(p, "authenticationMethodConfigurations"))
                t.AuthMethods[Str(m, "id")] = Str(m, "state").Equals("enabled", StringComparison.OrdinalIgnoreCase);
            t.AuthMethodsReadable = t.AuthMethods.Count > 0;
        });
    }

    internal static ConditionalAccessPolicyInfo ParseCaPolicy(JsonElement p)
    {
        var cond = Obj(p, "conditions");
        var users = Obj(cond, "users");
        var apps = Obj(cond, "applications");
        var grant = Obj(p, "grantControls");
        return new ConditionalAccessPolicyInfo
        {
            Id = Str(p, "id"),
            Name = Str(p, "displayName"),
            State = Str(p, "state"),
            GrantControls = Arr(grant, "builtInControls").Select(x => x.ToString()).ToList(),
            AuthenticationStrengthName = NullIfEmpty(Str(Obj(grant, "authenticationStrength"), "displayName")),
            IncludeUsers = Arr(users, "includeUsers").Select(x => x.ToString()).ToList(),
            IncludeRoles = Arr(users, "includeRoles").Select(x => x.ToString()).ToList(),
            IncludeApplications = Arr(apps, "includeApplications").Select(x => x.ToString()).ToList(),
            ClientAppTypes = Arr(cond, "clientAppTypes").Select(x => x.ToString()).ToList(),
            SignInRiskLevels = Arr(cond, "signInRiskLevels").Select(x => x.ToString()).ToList(),
            UserRiskLevels = Arr(cond, "userRiskLevels").Select(x => x.ToString()).ToList(),
        };
    }

    private static int? CountValue(List<JsonElement> items)
    {
        var first = items.FirstOrDefault();
        return first.ValueKind == JsonValueKind.Number && first.TryGetInt32(out var n) ? n
            : first.ValueKind == JsonValueKind.String && int.TryParse(first.GetString(), out var s) ? s
            : null;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    internal static T Base<T>(JsonElement row) where T : ResourceBase, new() => new()
    {
        Id = Str(row, "id"),
        Name = Str(row, "name"),
        ResourceGroup = Str(row, "resourceGroup"),
        SubscriptionId = Str(row, "subscriptionId"),
        Location = Str(row, "location"),
    };

    private static bool HasIdentity(JsonElement row)
    {
        var type = Str(Obj(row, "identity"), "type");
        return !string.IsNullOrEmpty(type) && !type.Equals("None", StringComparison.OrdinalIgnoreCase);
    }

    private const string ReaderNeeds = "Reader on the subscription";

    private async Task TryAsync(AuditScanResult r, AuditArea area, string source, string needs, string impact, Func<Task> action)
    {
        try { await action(); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { Issue(r, area, source, needs, impact, ex); }
    }

    private void Issue(AuditScanResult r, AuditArea area, string source, string needs, string impact, Exception ex)
    {
        _logger.LogWarning("{Source} could not be read: {Reason}. {Detail}", source, Describe(ex), Short(ex.Message));
        r.Issues.Add(new DataIssue
        {
            Area = area, Source = source, Reason = Describe(ex), Needs = needs, Impact = impact, Detail = Short(ex.Message),
            Fix = FixFor(Describe(ex), needs, r.SubscriptionIds.FirstOrDefault() ?? "<subscription-id>"),
        });
    }

    /// <summary>Concrete steps (and the command where there is one) that make the source readable.</summary>
    internal static string FixFor(string reason, string needs, string subscriptionId)
    {
        var graph = needs.Contains("Microsoft Graph", StringComparison.OrdinalIgnoreCase);
        if (reason.StartsWith("Permission denied", StringComparison.Ordinal))
        {
            if (graph)
            {
                var perm = needs.Replace("Microsoft Graph ", "", StringComparison.OrdinalIgnoreCase);
                var idx = perm.IndexOf(" (", StringComparison.Ordinal);
                var scope = idx > 0 ? perm[..idx] : perm;
                var role = idx > 0 ? perm[(idx + 2)..].TrimEnd(')') : "Global Reader";
                return $"Signed in with az login as a user: ask a Global Administrator to assign your account the {role} role " +
                       "(Microsoft Entra admin centre → Roles & admins → search the role → Add assignment), then run 'az logout' and 'az login' again so the new role is in the token. " +
                       $"Running as an app registration or managed identity: grant it the Microsoft Graph application permission {scope} and click 'Grant admin consent' " +
                       "(Entra admin centre → App registrations → the app → API permissions → Add a permission → Microsoft Graph → Application permissions).";
            }
            return $"Ask a subscription Owner to grant the signed-in identity {needs}: " +
                   $"az role assignment create --assignee \"<your-upn-or-identity-object-id>\" --role \"Reader\" --scope \"/subscriptions/{subscriptionId}\" " +
                   "— then press 'Audit this area' again.";
        }
        if (reason.StartsWith("Not authenticated", StringComparison.Ordinal) || reason.StartsWith("No token", StringComparison.Ordinal))
            return graph
                ? "Run 'az login' again (add --tenant <tenant-id> if the account spans tenants). Azure CLI must be able to issue Microsoft Graph tokens; if the app runs with a managed identity, make sure it has Graph permissions granted."
                : "Run 'az login' again (optionally --tenant <tenant-id>), then press Reload on the Scope step.";
        if (reason.StartsWith("Throttled", StringComparison.Ordinal) || reason.StartsWith("Azure returned a server error", StringComparison.Ordinal) || reason.StartsWith("Network", StringComparison.Ordinal))
            return "Transient: wait a minute, then press 'Audit this area' on the Grades step to read it again.";
        if (reason.StartsWith("Not found", StringComparison.Ordinal))
            return graph
                ? "The tenant does not expose this policy (often a licensing gap, e.g. no Entra ID P1/P2). Nothing to fix unless the feature is licensed."
                : $"Register the resource provider, e.g. az provider register --namespace Microsoft.Security --subscription \"{subscriptionId}\", or enable the feature in the portal, then audit the area again.";
        return "Review the detail below; if it persists, re-run the audit for this area from the Grades step.";
    }

    /// <summary>Turns an HTTP/SDK error into one plain sentence a reader can act on.</summary>
    internal static string Describe(Exception? ex)
    {
        if (ex is null) return "Unknown error";
        var m = ex.Message;
        bool Has(string text) => m.Contains(text, StringComparison.OrdinalIgnoreCase);
        if (Has("HTTP 403") || Has("(403)") || Has("AccessDenied") || Has("Authorization failed") || Has("AuthorizationFailed"))
            return "Permission denied (HTTP 403): the signed-in identity is not allowed to read this";
        if (Has("HTTP 401") || Has("(401)") || Has("InvalidAuthenticationToken"))
            return "Not authenticated for this API (HTTP 401): sign in again with az login";
        if (Has("HTTP 429") || Has("(429)") || Has("RateLimiting"))
            return "Throttled by Azure (HTTP 429): too many requests in a short time; retry in a minute";
        if (Has("HTTP 404") || Has("(404)"))
            return "Not found (HTTP 404): the resource provider is not registered or the feature is not enabled";
        if (Has("HTTP 400") || Has("(400)"))
            return "Rejected by Azure (HTTP 400): the request was not accepted for this subscription or tenant";
        if (Has("HTTP 5") || Has("InternalServerError"))
            return "Azure returned a server error (HTTP 5xx): transient, retry the audit";
        if (Has("Could not acquire a token"))
            return "No token for this API: the credential cannot sign in to it";
        if (ex is HttpRequestException || ex is TaskCanceledException)
            return "Network error or timeout reaching Azure";
        return "Unexpected error: " + Short(m);
    }

    private static string Short(string s) => s.Length <= 160 ? s : s[..160] + "…";
}
