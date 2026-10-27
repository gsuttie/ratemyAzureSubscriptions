using System.Text.Json;
using RateMyAzureSubscriptions.Models;
using RateMyAzureSubscriptions.Services;
using RateMyAzureSubscriptions.Services.Assessment;
using RateMyAzureSubscriptions.Services.Azure;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace RateMyAzureSubscriptions.Tests;

/// <summary>Parsing of the Azure Resource Graph / ARM / Graph JSON shapes the discovery service reads.</summary>
public class DiscoveryParsingTests
{
    private static JsonElement J(string json) => JsonDocument.Parse(json).RootElement.Clone();

    [Fact]
    public void ParsesVirtualMachine()
    {
        var vm = AuditDiscoveryService.ParseVm(J("""
        {
          "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1", "name": "vm1", "resourceGroup": "rg", "subscriptionId": "s", "location": "uksouth",
          "zones": ["1"], "identity": { "type": "SystemAssigned" }, "powerState": "PowerState/running",
          "properties": {
            "hardwareProfile": { "vmSize": "Standard_D2s_v5" },
            "storageProfile": { "osDisk": { "osType": "Linux", "managedDisk": { "id": "/d" } } },
            "diagnosticsProfile": { "bootDiagnostics": { "enabled": true } },
            "networkProfile": { "networkInterfaces": [ { "id": "/nic1" } ] },
            "licenseType": "RHEL_BYOS"
          }
        }
        """));
        Assert.Equal("vm1", vm.Name);
        Assert.Equal("Standard_D2s_v5", vm.Size);
        Assert.Equal("Linux", vm.OsType);
        Assert.Equal("running", vm.PowerState);
        Assert.True(vm.IsZonalOrInSet);
        Assert.True(vm.UsesManagedDisks);
        Assert.True(vm.BootDiagnosticsEnabled);
        Assert.True(vm.HasManagedIdentity);
        Assert.True(vm.HasHybridBenefit);
        Assert.Single(vm.NicIds);
    }

    [Fact]
    public void ParsesUnmanagedVmWithoutIdentity()
    {
        var vm = AuditDiscoveryService.ParseVm(J("""
        { "id": "/vm", "name": "old", "properties": { "hardwareProfile": { "vmSize": "Standard_A2" }, "storageProfile": { "osDisk": { "vhd": { "uri": "https://x/vhd" } } }, "osProfile": { "windowsConfiguration": {} } }, "identity": { "type": "None" } }
        """));
        Assert.False(vm.UsesManagedDisks);
        Assert.False(vm.HasManagedIdentity);
        Assert.Equal("Windows", vm.OsType);
        Assert.True(vm.IsPreviousGenerationSize);
    }

    [Fact]
    public void ParsesWebAppAndPlan()
    {
        var app = AuditDiscoveryService.ParseWebApp(J("""
        { "id": "/app", "name": "app", "kind": "functionapp,linux", "identity": { "type": "UserAssigned" }, "properties": { "state": "Running", "httpsOnly": false, "serverFarmId": "/plan", "siteConfig": { "minTlsVersion": "1.0", "ftpsState": "AllAllowed", "alwaysOn": false } } }
        """));
        Assert.True(app.IsFunctionApp);
        Assert.False(app.HttpsOnly);
        Assert.False(app.TlsOk);
        Assert.False(app.FtpsOk);
        Assert.True(app.HasManagedIdentity);
        Assert.Equal(false, app.AlwaysOn);

        var plan = AuditDiscoveryService.ParsePlan(J("""
        { "id": "/plan", "name": "plan", "sku": { "tier": "PremiumV3", "name": "P1v3", "capacity": 2 }, "properties": { "numberOfSites": 3, "zoneRedundant": true } }
        """));
        Assert.Equal(2, plan.Capacity);
        Assert.Equal(3, plan.NumberOfSites);
        Assert.True(plan.ZoneRedundant);
        Assert.False(plan.IsSingleInstanceProductionRisk);
    }

    [Fact]
    public void ParsesVNetSubnetsAndNsgRules()
    {
        var vnet = AuditDiscoveryService.ParseVNet(J("""
        { "id": "/vnet", "name": "vnet", "properties": { "addressSpace": { "addressPrefixes": ["10.0.0.0/16"] }, "enableDdosProtection": true, "virtualNetworkPeerings": [ {} ],
          "subnets": [ { "id": "/vnet/subnets/a", "name": "a", "properties": { "addressPrefix": "10.0.1.0/24", "networkSecurityGroup": { "id": "/nsg" } } },
                       { "id": "/vnet/subnets/GatewaySubnet", "name": "GatewaySubnet", "properties": { "addressPrefixes": ["10.0.255.0/27"] } },
                       { "id": "/vnet/subnets/d", "name": "d", "properties": { "addressPrefix": "10.0.2.0/24", "delegations": [ { "name": "x" } ] } } ] } }
        """));
        Assert.Equal(3, vnet.Subnets.Count);
        Assert.True(vnet.DdosProtectionEnabled);
        Assert.Equal(1, vnet.PeeringCount);
        Assert.Equal("/nsg", vnet.Subnets[0].NsgId);
        Assert.True(vnet.Subnets[1].IsPlatformSubnet);
        Assert.Equal("10.0.255.0/27", vnet.Subnets[1].AddressPrefix);
        Assert.True(vnet.Subnets[2].HasDelegation);

        var nsg = AuditDiscoveryService.ParseNsg(J("""
        { "id": "/nsg", "name": "nsg", "properties": { "subnets": [ {} ], "securityRules": [
            { "name": "rdp", "properties": { "priority": 100, "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "sourceAddressPrefix": "*", "destinationPortRanges": ["3389", "22"] } },
            { "name": "web", "properties": { "priority": 200, "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "sourceAddressPrefixes": ["Internet"], "destinationPortRange": "443" } } ] } }
        """));
        Assert.Equal(1, nsg.SubnetCount);
        Assert.False(nsg.IsOrphaned);
        Assert.Single(nsg.RiskyRules);
        Assert.Equal("rdp", nsg.RiskyRules[0].Name);
    }

    [Fact]
    public void ParsesPublicIpNicAndPrivateEndpoint()
    {
        var pip = AuditDiscoveryService.ParsePublicIp(J("""{ "id": "/pip", "name": "pip", "sku": { "name": "Standard" }, "properties": { "ipAddress": "1.2.3.4", "ipConfiguration": { "id": "/nic/ipConfigurations/c" } } }"""));
        Assert.True(pip.IsAttached);
        var orphan = AuditDiscoveryService.ParsePublicIp(J("""{ "id": "/pip2", "name": "pip2", "sku": { "name": "Basic" }, "properties": {} }"""));
        Assert.False(orphan.IsAttached);

        var nic = AuditDiscoveryService.ParseNic(J("""{ "id": "/nic", "name": "nic", "properties": { "virtualMachine": { "id": "/vm" }, "ipConfigurations": [ { "properties": { "publicIPAddress": { "id": "/pip" } } } ] } }"""));
        Assert.Equal("/vm", nic.VirtualMachineId);
        Assert.Single(nic.PublicIpIds);

        var pe = AuditDiscoveryService.ParsePrivateEndpoint(J("""{ "id": "/pe", "name": "pe", "properties": { "privateLinkServiceConnections": [ { "properties": { "privateLinkServiceId": "/st", "groupIds": ["blob"] } } ] } }"""));
        Assert.Equal("/st", pe.TargetResourceId);
        Assert.Equal("blob", pe.GroupId);
        Assert.True(NetworkingAssessor.ZoneMatches("privatelink.blob.core.windows.net", "blob"));
        Assert.True(NetworkingAssessor.ZoneMatches("privatelink.vaultcore.azure.net", "vault"));
        Assert.False(NetworkingAssessor.ZoneMatches("privatelink.blob.core.windows.net", "sqlServer"));
    }

    [Fact]
    public void ParsesStorageAccountAndBlobServiceProperties()
    {
        var sa = AuditDiscoveryService.ParseStorageAccount(J("""
        { "id": "/st", "name": "st", "kind": "StorageV2", "sku": { "name": "Standard_GRS" }, "properties": {
            "allowBlobPublicAccess": false, "supportsHttpsTrafficOnly": true, "minimumTlsVersion": "TLS1_2", "allowSharedKeyAccess": false,
            "publicNetworkAccess": "Enabled", "networkAcls": { "defaultAction": "Deny" }, "encryption": { "requireInfrastructureEncryption": true },
            "allowCrossTenantReplication": false, "defaultToOAuthAuthentication": true, "privateEndpointConnections": [ {} ] } }
        """));
        Assert.Equal(false, sa.AllowBlobPublicAccess);
        Assert.True(sa.TlsOk);
        Assert.True(sa.PublicNetworkRestricted);
        Assert.True(sa.IsRedundant);
        Assert.Equal("GRS", sa.RedundancyLabel);
        Assert.True(sa.InfrastructureEncryption);
        Assert.True(sa.HasPrivateEndpoint);
        Assert.False(sa.IsV1);

        AuditDiscoveryService.ApplyBlobServiceProperties(sa, J("""{ "properties": { "deleteRetentionPolicy": { "enabled": true, "days": 14 }, "containerDeleteRetentionPolicy": { "enabled": false }, "isVersioningEnabled": true } }"""));
        Assert.Equal(true, sa.BlobSoftDeleteEnabled);
        Assert.Equal(14, sa.BlobSoftDeleteDays);
        Assert.Equal(false, sa.ContainerSoftDeleteEnabled);
        Assert.Equal(true, sa.VersioningEnabled);
    }

    [Fact]
    public void ParsesKeyVaultAndSqlServer()
    {
        var kv = AuditDiscoveryService.ParseKeyVault(J("""{ "id": "/kv", "name": "kv", "properties": { "enableSoftDelete": true, "enablePurgeProtection": true, "enableRbacAuthorization": false, "publicNetworkAccess": "Enabled", "networkAcls": { "defaultAction": "Allow" } } }"""));
        Assert.True(kv.SoftDeleteEnabled && kv.PurgeProtectionEnabled);
        Assert.False(kv.RbacAuthorization);
        Assert.False(kv.PublicNetworkRestricted);

        var sql = AuditDiscoveryService.ParseSqlServer(J("""{ "id": "/sql", "name": "sql", "properties": { "minimalTlsVersion": "1.2", "publicNetworkAccess": "Disabled", "administrators": { "login": "admins", "azureADOnlyAuthentication": true } } }"""));
        Assert.True(sql.TlsOk && sql.PublicNetworkRestricted && sql.EntraOnlyAuthentication && sql.HasEntraAdmin);
    }

    [Fact]
    public void ParsesRoleAssignmentsAndCustomRoles()
    {
        var ra = AuditDiscoveryService.ParseRoleAssignment(J("""{ "id": "/subscriptions/s/providers/Microsoft.Authorization/roleAssignments/1", "subscriptionId": "s", "scope": "/subscriptions/s/resourceGroups/rg", "roleDefinitionId": "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "principalId": "p", "principalType": "ServicePrincipal" }"""));
        Assert.Equal("Resource group", ra.ScopeLevel);
        Assert.True(ra.IsServicePrincipal);
        Assert.Equal("Owner", AuditDiscoveryService.BuiltInRoleName(ra.RoleDefinitionId));
        Assert.Equal("Subscription", new RoleAssignmentInfo { Scope = "/subscriptions/s" }.ScopeLevel);
        Assert.Equal("Management group", new RoleAssignmentInfo { Scope = "/providers/Microsoft.Management/managementGroups/mg" }.ScopeLevel);
        Assert.Equal("Resource", new RoleAssignmentInfo { Scope = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st" }.ScopeLevel);

        var role = AuditDiscoveryService.ParseCustomRole(J("""{ "id": "/r", "roleName": "Super", "subscriptionId": "s", "permissions": [ { "actions": ["*"] } ], "assignableScopes": ["/subscriptions/s"] }"""));
        Assert.True(role.HasWildcardActions);
        var narrow = AuditDiscoveryService.ParseCustomRole(J("""{ "id": "/r2", "roleName": "VM ops", "permissions": [ { "actions": ["Microsoft.Compute/virtualMachines/start/action", "Microsoft.Compute/virtualMachines/*/read"] } ] }"""));
        Assert.False(narrow.HasWildcardActions);
    }

    [Fact]
    public void ParsesConditionalAccessPolicy()
    {
        var p = AuditDiscoveryService.ParseCaPolicy(J("""
        { "id": "1", "displayName": "MFA all", "state": "enabled",
          "conditions": { "users": { "includeUsers": ["All"], "includeRoles": [] }, "applications": { "includeApplications": ["All"] }, "clientAppTypes": ["all"], "signInRiskLevels": ["high"], "userRiskLevels": [] },
          "grantControls": { "operator": "OR", "builtInControls": ["mfa"], "authenticationStrength": null } }
        """));
        Assert.True(p.IsEnabled && p.AppliesToAllUsers && p.AppliesToAllApps && p.RequiresMfa && p.IsRiskBased);
        Assert.False(p.TargetsLegacyAuth);

        var legacy = AuditDiscoveryService.ParseCaPolicy(J("""{ "id": "2", "displayName": "Block legacy", "state": "enabled", "conditions": { "users": { "includeUsers": ["All"] }, "applications": { "includeApplications": ["All"] }, "clientAppTypes": ["exchangeActiveSync", "other"] }, "grantControls": { "builtInControls": ["block"] } }"""));
        Assert.True(legacy.TargetsLegacyAuth && legacy.Blocks);

        var strength = AuditDiscoveryService.ParseCaPolicy(J("""{ "id": "3", "displayName": "Admins", "state": "enabled", "conditions": { "users": { "includeRoles": ["62e90394-69f5-4237-9190-012177145e10"] }, "applications": { "includeApplications": ["All"] }, "clientAppTypes": ["all"] }, "grantControls": { "builtInControls": [], "authenticationStrength": { "displayName": "Phishing-resistant MFA" } } }"""));
        Assert.True(strength.TargetsAdminRoles && strength.RequiresMfa);
    }

    /// <summary>A canned IAzureApi that answers every Resource Graph query with an empty set, ARM/Graph with 404 or errors.</summary>
    private sealed class EmptyAzureApi : IAzureApi
    {
        public Task<List<JsonElement>> QueryResourceGraphAsync(string query, IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default) => Task.FromResult(new List<JsonElement>());
        public Task<List<JsonElement>> GetArmListAsync(string url, string? tenantId, CancellationToken ct = default) => Task.FromResult(new List<JsonElement>());
        public Task<JsonElement?> GetArmAsync(string url, string? tenantId, CancellationToken ct = default) => Task.FromResult<JsonElement?>(null);
        public Task<List<JsonElement>> GetGraphListAsync(string relativeUrl, string? tenantId, CancellationToken ct = default, bool consistencyLevelEventual = false) => throw new InvalidOperationException("HTTP 403: Insufficient privileges");
        public Task<JsonElement?> GetGraphAsync(string relativeUrl, string? tenantId, CancellationToken ct = default) => throw new InvalidOperationException("HTTP 403");
        public Task<List<JsonElement>> PostGraphAsync(string relativeUrl, string jsonBody, string? tenantId, CancellationToken ct = default) => throw new InvalidOperationException("HTTP 403");
    }

    [Fact]
    public async Task Scan_WithEmptySubscriptionsAndNoGraph_DegradesGracefully()
    {
        var svc = new AuditDiscoveryService(new EmptyAzureApi(), NullLogger<AuditDiscoveryService>.Instance);
        var scan = await svc.ScanAsync(["s1"], "t");
        Assert.Equal(6, scan.Ratings.Count);
        Assert.True(scan.Rating(AuditArea.EntraId)!.NotAssessed);
        Assert.True(scan.Rating(AuditArea.Compute)!.NotAssessed);
        Assert.False(scan.Rating(AuditArea.Security)!.NotAssessed); // subscription-level data always exists
        Assert.Single(scan.SubscriptionSecurity);
        Assert.Equal(false, scan.SubscriptionSecurity[0].ActivityLogExported);

        // Every unreadable source is explained next to its area: reason, what it needs, how to fix, impact.
        var entra = scan.Rating(AuditArea.EntraId)!;
        Assert.NotEmpty(entra.Issues);
        Assert.All(entra.Issues, i => Assert.StartsWith("Permission denied (HTTP 403)", i.Reason));
        Assert.All(entra.Issues, i => Assert.Contains("Microsoft Graph", i.Needs));
        Assert.All(entra.Issues, i => Assert.Contains("Grant admin consent", i.Fix));
        var iam = scan.Rating(AuditArea.Iam)!;
        Assert.Contains(iam.Issues, i => i.Source.Contains("App registration"));
        Assert.Empty(scan.Rating(AuditArea.Storage)!.Issues);
    }

    [Theory]
    [InlineData("HTTP 403: {\"error\":{\"code\":\"accessDenied\",\"message\":\"Request Authorization failed\"}}", "Permission denied (HTTP 403)")]
    [InlineData("Azure Resource Graph query failed (429): RateLimiting", "Throttled by Azure (HTTP 429)")]
    [InlineData("HTTP 500: InternalServerError", "Azure returned a server error")]
    [InlineData("HTTP 401: InvalidAuthenticationToken", "Not authenticated")]
    [InlineData("HTTP 404: not found", "Not found (HTTP 404)")]
    [InlineData("something odd", "Unexpected error")]
    public void Describe_TranslatesErrorsToPlainLanguage(string message, string expectedPrefix) =>
        Assert.StartsWith(expectedPrefix, AuditDiscoveryService.Describe(new InvalidOperationException(message)));

    [Fact]
    public void FixFor_GivesConcreteStepsPerCause()
    {
        var graph = AuditDiscoveryService.FixFor("Permission denied (HTTP 403): x", "Microsoft Graph Policy.Read.All (Global Reader)", "sub");
        Assert.Contains("Global Reader", graph);
        Assert.Contains("Policy.Read.All", graph);
        Assert.Contains("az login", graph);

        var rbac = AuditDiscoveryService.FixFor("Permission denied (HTTP 403): x", "Reader on the subscription", "sub-1");
        Assert.Contains("az role assignment create", rbac);
        Assert.Contains("/subscriptions/sub-1", rbac);

        Assert.Contains("wait a minute", AuditDiscoveryService.FixFor("Throttled by Azure (HTTP 429): x", "Reader on the subscription", "sub"));
        Assert.Contains("az login", AuditDiscoveryService.FixFor("Not authenticated for this API (HTTP 401): x", "Reader on the subscription", "sub"));
    }
}
