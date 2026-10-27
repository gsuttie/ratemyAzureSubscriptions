using RateMyAzureSubscriptions.Models;

namespace RateMyAzureSubscriptions.Services;

/// <summary>
/// A realistic sample estate so the app can be explored (and tested end to end) without Azure
/// credentials. Deliberately mixed: a well-run production subscription next to a neglected
/// dev/test one, so every grade band shows up somewhere.
/// </summary>
public static class DemoDataService
{
    public const string TenantId = "00000000-0000-0000-0000-00000000demo";
    public const string SubProd = "11111111-1111-1111-1111-111111111111";
    public const string SubDev = "22222222-2222-2222-2222-222222222222";

    public static List<SubscriptionInfo> Subscriptions() =>
    [
        new() { SubscriptionId = SubProd, DisplayName = "Contoso Production", State = "Enabled", TenantId = TenantId },
        new() { SubscriptionId = SubDev, DisplayName = "Contoso Dev/Test", State = "Enabled", TenantId = TenantId },
    ];

    public static Dictionary<string, TenantInfo> Tenants() => new(StringComparer.OrdinalIgnoreCase)
    {
        [TenantId] = new TenantInfo { TenantId = TenantId, DisplayName = "Contoso Ltd (demo)", DefaultDomain = "contoso.onmicrosoft.com" }
    };

    public static Dictionary<string, SubscriptionSummary> Summaries() => new(StringComparer.OrdinalIgnoreCase)
    {
        [SubProd] = new() { SubscriptionId = SubProd, ResourceCount = 86, ResourceGroupCount = 9 },
        [SubDev] = new() { SubscriptionId = SubDev, ResourceCount = 41, ResourceGroupCount = 6 },
    };

    private static string Rg(string sub, string rg) => $"/subscriptions/{sub}/resourceGroups/{rg}/providers";

    public static AuditScanResult Scan(IReadOnlyCollection<string> subscriptionIds, IReadOnlyCollection<AuditArea>? areas = null)
    {
        var all = Estate();
        var subs = new HashSet<string>(subscriptionIds, StringComparer.OrdinalIgnoreCase);
        var r = new AuditScanResult { SubscriptionIds = subscriptionIds.ToList(), TenantId = TenantId, Entra = all.Entra };
        if (areas is not null) r.AssessedAreas = new HashSet<AuditArea>(areas);

        r.VirtualMachines = all.VirtualMachines.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.Disks = all.Disks.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.WebApps = all.WebApps.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.AppServicePlans = all.AppServicePlans.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.VirtualNetworks = all.VirtualNetworks.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.NetworkSecurityGroups = all.NetworkSecurityGroups.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.PublicIps = all.PublicIps.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.NetworkInterfaces = all.NetworkInterfaces.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.PrivateEndpoints = all.PrivateEndpoints.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.NetworkWatchers = all.NetworkWatchers.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.FlowLogs = all.FlowLogs.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.PrivateDnsZones = all.PrivateDnsZones.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.BastionCount = subs.Contains(SubProd) ? all.BastionCount : 0;
        r.FirewallCount = subs.Contains(SubProd) ? all.FirewallCount : 0;
        r.StorageAccounts = all.StorageAccounts.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.KeyVaults = all.KeyVaults.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.SqlServers = all.SqlServers.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.SubscriptionSecurity = all.SubscriptionSecurity.Where(x => subs.Contains(x.SubscriptionId)).ToList();
        r.Iam = new IamInfo
        {
            RoleAssignments = all.Iam.RoleAssignments.Where(x => subs.Contains(x.SubscriptionId)).ToList(),
            CustomRoles = all.Iam.CustomRoles.Where(x => subs.Contains(x.SubscriptionId)).ToList(),
            UserAssignedIdentities = all.Iam.UserAssignedIdentities.Where(x => subs.Contains(x.SubscriptionId)).ToList(),
            PrincipalsResolved = true,
            AppsWithExpiredCredentials = 3,
            AppsWithLongLivedCredentials = 2,
        };
        r.Warnings.Add("Sample data: this estate is built in and nothing was read from Azure.");

        AuditDiscoveryService.Finalize(r);
        return r;
    }

    public static AuditScanResult Estate()
    {
        var r = new AuditScanResult { SubscriptionIds = [SubProd, SubDev], TenantId = TenantId };

        // ── Compute ──────────────────────────────────────────────────────────
        var prodVnet = $"{Rg(SubProd, "rg-network")}/Microsoft.Network/virtualNetworks/vnet-prod";
        var devVnet = $"{Rg(SubDev, "rg-dev")}/Microsoft.Network/virtualNetworks/vnet-dev";

        r.VirtualMachines =
        [
            new() { Id = $"{Rg(SubProd, "rg-app")}/Microsoft.Compute/virtualMachines/vm-app-01", Name = "vm-app-01", ResourceGroup = "rg-app", SubscriptionId = SubProd, Location = "uksouth", Size = "Standard_D4s_v5", OsType = "Windows", PowerState = "running", Zones = ["1"], UsesManagedDisks = true, BootDiagnosticsEnabled = true, HasManagedIdentity = true, LicenseType = "Windows_Server", IsBackedUp = true, NicIds = [$"{Rg(SubProd, "rg-app")}/Microsoft.Network/networkInterfaces/nic-app-01"] },
            new() { Id = $"{Rg(SubProd, "rg-app")}/Microsoft.Compute/virtualMachines/vm-app-02", Name = "vm-app-02", ResourceGroup = "rg-app", SubscriptionId = SubProd, Location = "uksouth", Size = "Standard_D4s_v5", OsType = "Windows", PowerState = "running", Zones = ["2"], UsesManagedDisks = true, BootDiagnosticsEnabled = true, HasManagedIdentity = true, LicenseType = "Windows_Server", IsBackedUp = true, NicIds = [$"{Rg(SubProd, "rg-app")}/Microsoft.Network/networkInterfaces/nic-app-02"] },
            new() { Id = $"{Rg(SubProd, "rg-data")}/Microsoft.Compute/virtualMachines/vm-sql-01", Name = "vm-sql-01", ResourceGroup = "rg-data", SubscriptionId = SubProd, Location = "uksouth", Size = "Standard_E8s_v5", OsType = "Windows", PowerState = "running", AvailabilitySetId = $"{Rg(SubProd, "rg-data")}/Microsoft.Compute/availabilitySets/as-sql", UsesManagedDisks = true, BootDiagnosticsEnabled = true, HasManagedIdentity = false, LicenseType = "", IsBackedUp = true, NicIds = [$"{Rg(SubProd, "rg-data")}/Microsoft.Network/networkInterfaces/nic-sql-01"] },
            new() { Id = $"{Rg(SubDev, "rg-dev")}/Microsoft.Compute/virtualMachines/vm-dev-jump", Name = "vm-dev-jump", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", Size = "Standard_D2_v2", OsType = "Windows", PowerState = "running", UsesManagedDisks = true, BootDiagnosticsEnabled = false, HasManagedIdentity = false, IsBackedUp = false, NicIds = [$"{Rg(SubDev, "rg-dev")}/Microsoft.Network/networkInterfaces/nic-dev-jump"] },
            new() { Id = $"{Rg(SubDev, "rg-dev")}/Microsoft.Compute/virtualMachines/vm-dev-build", Name = "vm-dev-build", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", Size = "Standard_A4", OsType = "Linux", PowerState = "stopped", UsesManagedDisks = false, BootDiagnosticsEnabled = false, HasManagedIdentity = false, IsBackedUp = false, NicIds = [$"{Rg(SubDev, "rg-dev")}/Microsoft.Network/networkInterfaces/nic-dev-build"] },
            new() { Id = $"{Rg(SubDev, "rg-restore-test")}/Microsoft.Compute/virtualMachines/vm-crm-restore-01", Name = "vm-crm-restore-01", ResourceGroup = "rg-restore-test", SubscriptionId = SubDev, Location = "ukwest", Size = "Standard_A2", OsType = "Windows", PowerState = "stopped", UsesManagedDisks = false, BootDiagnosticsEnabled = false, HasManagedIdentity = false, IsBackedUp = false },
            new() { Id = $"{Rg(SubDev, "rg-legacy")}/Microsoft.Compute/virtualMachines/vm-legacy-crm", Name = "vm-legacy-crm", ResourceGroup = "rg-legacy", SubscriptionId = SubDev, Location = "ukwest", Size = "Standard_DS3", OsType = "Windows", PowerState = "deallocated", UsesManagedDisks = true, BootDiagnosticsEnabled = true, HasManagedIdentity = false, IsBackedUp = false, NicIds = [$"{Rg(SubDev, "rg-legacy")}/Microsoft.Network/networkInterfaces/nic-legacy-crm"] },
        ];

        r.Disks =
        [
            new() { Id = $"{Rg(SubProd, "rg-app")}/Microsoft.Compute/disks/vm-app-01_OsDisk", Name = "vm-app-01_OsDisk", ResourceGroup = "rg-app", SubscriptionId = SubProd, Location = "uksouth", SizeGb = 128, Sku = "Premium_LRS", DiskState = "Attached" },
            new() { Id = $"{Rg(SubProd, "rg-app")}/Microsoft.Compute/disks/vm-app-02_OsDisk", Name = "vm-app-02_OsDisk", ResourceGroup = "rg-app", SubscriptionId = SubProd, Location = "uksouth", SizeGb = 128, Sku = "Premium_LRS", DiskState = "Attached" },
            new() { Id = $"{Rg(SubProd, "rg-data")}/Microsoft.Compute/disks/vm-sql-01_data", Name = "vm-sql-01_data", ResourceGroup = "rg-data", SubscriptionId = SubProd, Location = "uksouth", SizeGb = 1024, Sku = "Premium_LRS", DiskState = "Attached" },
            new() { Id = $"{Rg(SubDev, "rg-dev")}/Microsoft.Compute/disks/vm-dev-old_OsDisk", Name = "vm-dev-old_OsDisk", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", SizeGb = 256, Sku = "Premium_LRS", DiskState = "Unattached" },
            new() { Id = $"{Rg(SubDev, "rg-dev")}/Microsoft.Compute/disks/data-scratch-01", Name = "data-scratch-01", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", SizeGb = 512, Sku = "StandardSSD_LRS", DiskState = "Unattached" },
        ];

        r.AppServicePlans =
        [
            new() { Id = $"{Rg(SubProd, "rg-web")}/Microsoft.Web/serverfarms/asp-prod", Name = "asp-prod", ResourceGroup = "rg-web", SubscriptionId = SubProd, Location = "uksouth", SkuTier = "PremiumV3", SkuName = "P1v3", Capacity = 2, NumberOfSites = 2, ZoneRedundant = true },
            new() { Id = $"{Rg(SubDev, "rg-dev")}/Microsoft.Web/serverfarms/asp-dev", Name = "asp-dev", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", SkuTier = "Standard", SkuName = "S1", Capacity = 1, NumberOfSites = 2 },
            new() { Id = $"{Rg(SubDev, "rg-dev")}/Microsoft.Web/serverfarms/asp-poc-2022", Name = "asp-poc-2022", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", SkuTier = "Basic", SkuName = "B1", Capacity = 1, NumberOfSites = 0 },
            new() { Id = $"{Rg(SubDev, "rg-legacy")}/Microsoft.Web/serverfarms/asp-free", Name = "asp-free", ResourceGroup = "rg-legacy", SubscriptionId = SubDev, Location = "ukwest", SkuTier = "Free", SkuName = "F1", Capacity = 1, NumberOfSites = 1 },
        ];

        r.WebApps =
        [
            new() { Id = $"{Rg(SubProd, "rg-web")}/Microsoft.Web/sites/app-contoso-portal", Name = "app-contoso-portal", ResourceGroup = "rg-web", SubscriptionId = SubProd, Location = "uksouth", Kind = "app", State = "Running", HttpsOnly = true, MinTlsVersion = "1.2", FtpsState = "Disabled", AlwaysOn = true, HasManagedIdentity = true, ServerFarmId = r.AppServicePlans[0].Id, PublicNetworkAccess = "Enabled" },
            new() { Id = $"{Rg(SubProd, "rg-web")}/Microsoft.Web/sites/func-contoso-orders", Name = "func-contoso-orders", ResourceGroup = "rg-web", SubscriptionId = SubProd, Location = "uksouth", Kind = "functionapp", State = "Running", HttpsOnly = true, MinTlsVersion = "1.2", FtpsState = "FtpsOnly", HasManagedIdentity = true, ServerFarmId = r.AppServicePlans[0].Id },
            new() { Id = $"{Rg(SubDev, "rg-dev")}/Microsoft.Web/sites/app-contoso-dev", Name = "app-contoso-dev", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", Kind = "app", State = "Running", HttpsOnly = false, MinTlsVersion = "1.0", FtpsState = "AllAllowed", AlwaysOn = false, HasManagedIdentity = false, ServerFarmId = r.AppServicePlans[1].Id },
            new() { Id = $"{Rg(SubDev, "rg-dev")}/Microsoft.Web/sites/api-contoso-dev", Name = "api-contoso-dev", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", Kind = "app,linux", State = "Running", HttpsOnly = true, MinTlsVersion = "1.2", FtpsState = "Disabled", AlwaysOn = false, HasManagedIdentity = false, ServerFarmId = r.AppServicePlans[1].Id },
            new() { Id = $"{Rg(SubDev, "rg-legacy")}/Microsoft.Web/sites/app-intranet-old", Name = "app-intranet-old", ResourceGroup = "rg-legacy", SubscriptionId = SubDev, Location = "ukwest", Kind = "app", State = "Running", HttpsOnly = false, MinTlsVersion = "1.0", FtpsState = "AllAllowed", AlwaysOn = false, HasManagedIdentity = false, ServerFarmId = r.AppServicePlans[3].Id },
        ];

        // ── Networking ───────────────────────────────────────────────────────
        var nsgApp = $"{Rg(SubProd, "rg-network")}/Microsoft.Network/networkSecurityGroups/nsg-app";
        var nsgData = $"{Rg(SubProd, "rg-network")}/Microsoft.Network/networkSecurityGroups/nsg-data";
        var nsgDev = $"{Rg(SubDev, "rg-dev")}/Microsoft.Network/networkSecurityGroups/nsg-dev";
        var nsgOld = $"{Rg(SubDev, "rg-legacy")}/Microsoft.Network/networkSecurityGroups/nsg-old-2019";

        r.VirtualNetworks =
        [
            new() { Id = prodVnet, Name = "vnet-prod", ResourceGroup = "rg-network", SubscriptionId = SubProd, Location = "uksouth", AddressSpaces = ["10.10.0.0/16"], DdosProtectionEnabled = true, PeeringCount = 1, Subnets =
            [
                new() { Id = $"{prodVnet}/subnets/snet-app", Name = "snet-app", AddressPrefix = "10.10.1.0/24", NsgId = nsgApp },
                new() { Id = $"{prodVnet}/subnets/snet-data", Name = "snet-data", AddressPrefix = "10.10.2.0/24", NsgId = nsgData },
                new() { Id = $"{prodVnet}/subnets/snet-pe", Name = "snet-pe", AddressPrefix = "10.10.3.0/24", NsgId = nsgApp },
                new() { Id = $"{prodVnet}/subnets/AzureBastionSubnet", Name = "AzureBastionSubnet", AddressPrefix = "10.10.250.0/26" },
            ]},
            new() { Id = devVnet, Name = "vnet-dev", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", AddressSpaces = ["10.20.0.0/16"], DdosProtectionEnabled = false, Subnets =
            [
                new() { Id = $"{devVnet}/subnets/default", Name = "default", AddressPrefix = "10.20.0.0/24", NsgId = nsgDev },
                new() { Id = $"{devVnet}/subnets/snet-build", Name = "snet-build", AddressPrefix = "10.20.1.0/24" },
                new() { Id = $"{devVnet}/subnets/snet-legacy", Name = "snet-legacy", AddressPrefix = "10.20.2.0/24" },
            ]},
        ];

        r.NetworkSecurityGroups =
        [
            new() { Id = nsgApp, Name = "nsg-app", ResourceGroup = "rg-network", SubscriptionId = SubProd, Location = "uksouth", SubnetCount = 2, Rules =
            [
                new() { Name = "allow-https-from-agw", Priority = 100, Direction = "Inbound", Access = "Allow", Protocol = "Tcp", Sources = ["10.10.0.0/24"], DestinationPorts = ["443"] },
                new() { Name = "deny-all-inbound", Priority = 4000, Direction = "Inbound", Access = "Deny", Protocol = "*", Sources = ["*"], DestinationPorts = ["*"] },
            ]},
            new() { Id = nsgData, Name = "nsg-data", ResourceGroup = "rg-network", SubscriptionId = SubProd, Location = "uksouth", SubnetCount = 1, Rules =
            [
                new() { Name = "allow-sql-from-app", Priority = 100, Direction = "Inbound", Access = "Allow", Protocol = "Tcp", Sources = ["10.10.1.0/24"], DestinationPorts = ["1433"] },
            ]},
            new() { Id = nsgDev, Name = "nsg-dev", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", SubnetCount = 1, Rules =
            [
                new() { Name = "allow-rdp-any", Priority = 100, Direction = "Inbound", Access = "Allow", Protocol = "Tcp", Sources = ["*"], DestinationPorts = ["3389"] },
                new() { Name = "allow-ssh-internet", Priority = 110, Direction = "Inbound", Access = "Allow", Protocol = "Tcp", Sources = ["Internet"], DestinationPorts = ["22"] },
                new() { Name = "allow-web", Priority = 200, Direction = "Inbound", Access = "Allow", Protocol = "Tcp", Sources = ["*"], DestinationPorts = ["80", "443"] },
            ]},
            new() { Id = nsgOld, Name = "nsg-old-2019", ResourceGroup = "rg-legacy", SubscriptionId = SubDev, Location = "ukwest", Rules = [] },
        ];

        var pipDevJump = $"{Rg(SubDev, "rg-dev")}/Microsoft.Network/publicIPAddresses/pip-dev-jump";
        r.PublicIps =
        [
            new() { Id = $"{Rg(SubProd, "rg-network")}/Microsoft.Network/publicIPAddresses/pip-agw-prod", Name = "pip-agw-prod", ResourceGroup = "rg-network", SubscriptionId = SubProd, Location = "uksouth", IpAddress = "20.90.10.11", Sku = "Standard", AttachedToId = $"{Rg(SubProd, "rg-network")}/Microsoft.Network/applicationGateways/agw-prod/frontendIPConfigurations/public" },
            new() { Id = $"{Rg(SubProd, "rg-network")}/Microsoft.Network/publicIPAddresses/pip-bastion", Name = "pip-bastion", ResourceGroup = "rg-network", SubscriptionId = SubProd, Location = "uksouth", IpAddress = "20.90.10.12", Sku = "Standard", AttachedToId = $"{Rg(SubProd, "rg-network")}/Microsoft.Network/bastionHosts/bas-prod/bastionHostIpConfigurations/ipconf" },
            new() { Id = pipDevJump, Name = "pip-dev-jump", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", IpAddress = "20.90.20.5", Sku = "Standard", AttachedToId = $"{Rg(SubDev, "rg-dev")}/Microsoft.Network/networkInterfaces/nic-dev-jump/ipConfigurations/ipconfig1" },
            new() { Id = $"{Rg(SubDev, "rg-dev")}/Microsoft.Network/publicIPAddresses/pip-unused-01", Name = "pip-unused-01", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", IpAddress = "20.90.20.6", Sku = "Standard" },
            new() { Id = $"{Rg(SubDev, "rg-legacy")}/Microsoft.Network/publicIPAddresses/pip-old-lb", Name = "pip-old-lb", ResourceGroup = "rg-legacy", SubscriptionId = SubDev, Location = "ukwest", IpAddress = "", Sku = "Basic" },
        ];

        r.NetworkInterfaces =
        [
            new() { Id = $"{Rg(SubProd, "rg-app")}/Microsoft.Network/networkInterfaces/nic-app-01", Name = "nic-app-01", ResourceGroup = "rg-app", SubscriptionId = SubProd, Location = "uksouth", VirtualMachineId = r.VirtualMachines[0].Id },
            new() { Id = $"{Rg(SubProd, "rg-app")}/Microsoft.Network/networkInterfaces/nic-app-02", Name = "nic-app-02", ResourceGroup = "rg-app", SubscriptionId = SubProd, Location = "uksouth", VirtualMachineId = r.VirtualMachines[1].Id },
            new() { Id = $"{Rg(SubProd, "rg-data")}/Microsoft.Network/networkInterfaces/nic-sql-01", Name = "nic-sql-01", ResourceGroup = "rg-data", SubscriptionId = SubProd, Location = "uksouth", VirtualMachineId = r.VirtualMachines[2].Id },
            new() { Id = $"{Rg(SubDev, "rg-dev")}/Microsoft.Network/networkInterfaces/nic-dev-jump", Name = "nic-dev-jump", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", VirtualMachineId = r.VirtualMachines[3].Id, PublicIpIds = [pipDevJump] },
            new() { Id = $"{Rg(SubDev, "rg-dev")}/Microsoft.Network/networkInterfaces/nic-dev-build", Name = "nic-dev-build", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", VirtualMachineId = r.VirtualMachines[4].Id },
            new() { Id = $"{Rg(SubDev, "rg-legacy")}/Microsoft.Network/networkInterfaces/nic-legacy-crm", Name = "nic-legacy-crm", ResourceGroup = "rg-legacy", SubscriptionId = SubDev, Location = "ukwest", VirtualMachineId = r.VirtualMachines[5].Id },
        ];

        var stProd = $"{Rg(SubProd, "rg-data")}/Microsoft.Storage/storageAccounts/stcontosoprod";
        var kvProd = $"{Rg(SubProd, "rg-security")}/Microsoft.KeyVault/vaults/kv-contoso-prod";
        r.PrivateEndpoints =
        [
            new() { Id = $"{Rg(SubProd, "rg-network")}/Microsoft.Network/privateEndpoints/pe-stcontosoprod-blob", Name = "pe-stcontosoprod-blob", ResourceGroup = "rg-network", SubscriptionId = SubProd, Location = "uksouth", TargetResourceId = stProd, GroupId = "blob" },
            new() { Id = $"{Rg(SubProd, "rg-network")}/Microsoft.Network/privateEndpoints/pe-kv-prod", Name = "pe-kv-prod", ResourceGroup = "rg-network", SubscriptionId = SubProd, Location = "uksouth", TargetResourceId = kvProd, GroupId = "vault" },
            new() { Id = $"{Rg(SubProd, "rg-network")}/Microsoft.Network/privateEndpoints/pe-sql-prod", Name = "pe-sql-prod", ResourceGroup = "rg-network", SubscriptionId = SubProd, Location = "uksouth", TargetResourceId = $"{Rg(SubProd, "rg-data")}/Microsoft.Sql/servers/sql-contoso-prod", GroupId = "sqlServer" },
        ];
        r.PrivateDnsZones =
        [
            new() { Id = $"{Rg(SubProd, "rg-network")}/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net", Name = "privatelink.blob.core.windows.net", ResourceGroup = "rg-network", SubscriptionId = SubProd, Location = "global" },
            new() { Id = $"{Rg(SubProd, "rg-network")}/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net", Name = "privatelink.vaultcore.azure.net", ResourceGroup = "rg-network", SubscriptionId = SubProd, Location = "global" },
        ];
        r.NetworkWatchers =
        [
            new() { Id = $"{Rg(SubProd, "NetworkWatcherRG")}/Microsoft.Network/networkWatchers/NetworkWatcher_uksouth", Name = "NetworkWatcher_uksouth", ResourceGroup = "NetworkWatcherRG", SubscriptionId = SubProd, Location = "uksouth" },
        ];
        r.FlowLogs =
        [
            new() { Id = $"{Rg(SubProd, "NetworkWatcherRG")}/Microsoft.Network/networkWatchers/NetworkWatcher_uksouth/flowLogs/vnet-prod-flow", Name = "vnet-prod-flow", ResourceGroup = "NetworkWatcherRG", SubscriptionId = SubProd, Location = "uksouth", TargetResourceId = prodVnet, Enabled = true },
        ];
        r.BastionCount = 1;
        r.FirewallCount = 1;

        // ── Storage ──────────────────────────────────────────────────────────
        r.StorageAccounts =
        [
            new() { Id = stProd, Name = "stcontosoprod", ResourceGroup = "rg-data", SubscriptionId = SubProd, Location = "uksouth", Kind = "StorageV2", SkuName = "Standard_ZRS", AccessTier = "Hot", AllowBlobPublicAccess = false, SupportsHttpsTrafficOnly = true, MinimumTlsVersion = "TLS1_2", AllowSharedKeyAccess = false, PublicNetworkAccess = "Disabled", NetworkDefaultAction = "Deny", InfrastructureEncryption = true, AllowCrossTenantReplication = false, DefaultToOAuthAuthentication = true, BlobSoftDeleteEnabled = true, BlobSoftDeleteDays = 14, ContainerSoftDeleteEnabled = true, VersioningEnabled = true, HasLifecyclePolicy = true },
            new() { Id = $"{Rg(SubProd, "rg-web")}/Microsoft.Storage/storageAccounts/stcontosoweb", Name = "stcontosoweb", ResourceGroup = "rg-web", SubscriptionId = SubProd, Location = "uksouth", Kind = "StorageV2", SkuName = "Standard_GRS", AccessTier = "Hot", AllowBlobPublicAccess = false, SupportsHttpsTrafficOnly = true, MinimumTlsVersion = "TLS1_2", AllowSharedKeyAccess = true, PublicNetworkAccess = "Enabled", NetworkDefaultAction = "Deny", InfrastructureEncryption = false, AllowCrossTenantReplication = false, DefaultToOAuthAuthentication = false, BlobSoftDeleteEnabled = true, BlobSoftDeleteDays = 7, ContainerSoftDeleteEnabled = false, VersioningEnabled = false, HasLifecyclePolicy = false },
            new() { Id = $"{Rg(SubDev, "rg-dev")}/Microsoft.Storage/storageAccounts/stcontosodev", Name = "stcontosodev", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", Kind = "StorageV2", SkuName = "Standard_LRS", AccessTier = "Hot", AllowBlobPublicAccess = true, SupportsHttpsTrafficOnly = true, MinimumTlsVersion = "TLS1_0", AllowSharedKeyAccess = true, PublicNetworkAccess = "Enabled", NetworkDefaultAction = "Allow", InfrastructureEncryption = false, AllowCrossTenantReplication = true, DefaultToOAuthAuthentication = false, BlobSoftDeleteEnabled = false, ContainerSoftDeleteEnabled = false, VersioningEnabled = false, HasLifecyclePolicy = false },
            new() { Id = $"{Rg(SubDev, "rg-dev")}/Microsoft.Storage/storageAccounts/strestorevalidation", Name = "strestorevalidation", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", Kind = "Storage", SkuName = "Standard_LRS", AllowBlobPublicAccess = true, SupportsHttpsTrafficOnly = false, MinimumTlsVersion = "TLS1_0" },
            new() { Id = $"{Rg(SubDev, "rg-legacy")}/Microsoft.Storage/storageAccounts/contosolegacyvhds", Name = "contosolegacyvhds", ResourceGroup = "rg-legacy", SubscriptionId = SubDev, Location = "ukwest", Kind = "Storage", SkuName = "Standard_LRS", AllowBlobPublicAccess = null, SupportsHttpsTrafficOnly = false, MinimumTlsVersion = "", AllowSharedKeyAccess = null, PublicNetworkAccess = "", NetworkDefaultAction = "Allow", InfrastructureEncryption = false, AllowCrossTenantReplication = null, DefaultToOAuthAuthentication = null, BlobSoftDeleteEnabled = false, ContainerSoftDeleteEnabled = false, VersioningEnabled = false, HasLifecyclePolicy = false },
        ];

        // ── Security ─────────────────────────────────────────────────────────
        r.KeyVaults =
        [
            new() { Id = kvProd, Name = "kv-contoso-prod", ResourceGroup = "rg-security", SubscriptionId = SubProd, Location = "uksouth", SoftDeleteEnabled = true, PurgeProtectionEnabled = true, RbacAuthorization = true, PublicNetworkAccess = "Disabled", NetworkDefaultAction = "Deny" },
            new() { Id = $"{Rg(SubDev, "rg-dev")}/Microsoft.KeyVault/vaults/kv-contoso-dev", Name = "kv-contoso-dev", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", SoftDeleteEnabled = true, PurgeProtectionEnabled = false, RbacAuthorization = false, PublicNetworkAccess = "Enabled", NetworkDefaultAction = "Allow" },
        ];
        r.SqlServers =
        [
            new() { Id = $"{Rg(SubProd, "rg-data")}/Microsoft.Sql/servers/sql-contoso-prod", Name = "sql-contoso-prod", ResourceGroup = "rg-data", SubscriptionId = SubProd, Location = "uksouth", MinimalTlsVersion = "1.2", PublicNetworkAccess = "Disabled", EntraOnlyAuthentication = true, HasEntraAdmin = true },
            new() { Id = $"{Rg(SubDev, "rg-dev")}/Microsoft.Sql/servers/sql-contoso-dev", Name = "sql-contoso-dev", ResourceGroup = "rg-dev", SubscriptionId = SubDev, Location = "uksouth", MinimalTlsVersion = "1.0", PublicNetworkAccess = "Enabled", EntraOnlyAuthentication = false, HasEntraAdmin = false },
        ];
        r.SubscriptionSecurity =
        [
            new()
            {
                SubscriptionId = SubProd,
                DefenderPlans = new(StringComparer.OrdinalIgnoreCase) { ["VirtualMachines"] = "Standard", ["StorageAccounts"] = "Standard", ["KeyVaults"] = "Standard", ["SqlServers"] = "Standard", ["AppServices"] = "Standard", ["Arm"] = "Standard", ["Containers"] = "Free" },
                SecurityContactConfigured = true, SecureScorePercent = 78, HealthyAssessments = 142, UnhealthyAssessments = 23, HighSeverityUnhealthy = 2,
                ActivityLogExported = true, ActivityLogDestinations = ["Log Analytics: law-contoso-prod"], LogAnalyticsWorkspaceCount = 1,
                PolicyAssignmentCount = 6, HasSecurityBenchmarkAssignment = true, PolicyAssignmentNames = ["Microsoft cloud security benchmark", "Allowed locations", "Require tag: owner", "Deny public IPs on NICs", "Audit diagnostics", "Inherit tags from RG"],
            },
            new()
            {
                SubscriptionId = SubDev,
                DefenderPlans = new(StringComparer.OrdinalIgnoreCase) { ["VirtualMachines"] = "Free", ["StorageAccounts"] = "Free", ["KeyVaults"] = "Free", ["SqlServers"] = "Free", ["AppServices"] = "Free", ["Arm"] = "Free" },
                SecurityContactConfigured = false, SecureScorePercent = 41, HealthyAssessments = 38, UnhealthyAssessments = 61, HighSeverityUnhealthy = 14,
                ActivityLogExported = false, LogAnalyticsWorkspaceCount = 0,
                PolicyAssignmentCount = 0, HasSecurityBenchmarkAssignment = false,
            },
        ];

        // ── Microsoft Entra ID ───────────────────────────────────────────────
        r.Entra = new EntraTenantInfo
        {
            TenantId = TenantId, DisplayName = "Contoso Ltd (demo)", DefaultDomain = "contoso.onmicrosoft.com",
            SecurityDefaultsEnabled = false, ConditionalAccessReadable = true, AuthorizationPolicyReadable = true, RolesReadable = true, AuthMethodsReadable = true,
            ConditionalAccessPolicies =
            [
                new() { Id = "ca-1", Name = "CA001 Require MFA for admins", State = "enabled", GrantControls = ["mfa"], IncludeRoles = ["62e90394-69f5-4237-9190-012177145e10", "e8611ab8-c189-46e8-94e1-60213ab1f814"], IncludeApplications = ["All"], ClientAppTypes = ["all"] },
                new() { Id = "ca-2", Name = "CA002 Require MFA for all users", State = "enabledForReportingButNotEnforced", GrantControls = ["mfa"], IncludeUsers = ["All"], IncludeApplications = ["All"], ClientAppTypes = ["all"] },
                new() { Id = "ca-3", Name = "CA003 Block legacy authentication", State = "enabled", GrantControls = ["block"], IncludeUsers = ["All"], IncludeApplications = ["All"], ClientAppTypes = ["exchangeActiveSync", "other"] },
                new() { Id = "ca-4", Name = "CA004 Require compliant device for Office 365", State = "disabled", GrantControls = ["compliantDevice"], IncludeUsers = ["All"], IncludeApplications = ["Office365"], ClientAppTypes = ["all"] },
            ],
            AllowInvitesFrom = "everyone", GuestUserRoleId = "a0b1b346-4d3e-4e8b-98f8-753987be4970",
            UsersCanRegisterApps = true, UsersCanCreateTenants = false, UsersCanCreateSecurityGroups = true, UserConsentAllowed = true,
            GlobalAdminCount = 7, GlobalAdminNames = ["Alex Morgan", "Sam Patel", "Jordan Lee", "breakglass-01", "svc-m365-migration", "Taylor Kim", "Chris Evans (Partner)"], GuestsInPrivilegedRoles = 1, PrivilegedRoleMemberCount = 12,
            UserCount = 412, GuestCount = 37,
            AuthMethods = new(StringComparer.OrdinalIgnoreCase) { ["MicrosoftAuthenticator"] = true, ["Fido2"] = false, ["Sms"] = true, ["Voice"] = false, ["Email"] = true, ["TemporaryAccessPass"] = true },
        };

        // ── IAM ──────────────────────────────────────────────────────────────
        RoleAssignmentInfo A(string sub, string scope, string role, string principalType, string name, bool guest = false, bool orphaned = false) => new()
        {
            Id = $"{scope}/providers/Microsoft.Authorization/roleAssignments/{Guid.NewGuid():D}", SubscriptionId = sub, Scope = scope, RoleName = role,
            RoleDefinitionId = $"/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions/{role.ToLowerInvariant().Replace(' ', '-')}",
            PrincipalId = Guid.NewGuid().ToString("D"), PrincipalType = principalType, PrincipalName = name, IsGuest = guest, IsOrphaned = orphaned,
        };
        var prodScope = $"/subscriptions/{SubProd}";
        var devScope = $"/subscriptions/{SubDev}";
        r.Iam = new IamInfo
        {
            PrincipalsResolved = true, AppsWithExpiredCredentials = 3, AppsWithLongLivedCredentials = 2,
            RoleAssignments =
            [
                A(SubProd, prodScope, "Owner", "Group", "sg-azure-platform-owners"),
                A(SubProd, prodScope, "Contributor", "Group", "sg-azure-prod-contributors"),
                A(SubProd, prodScope, "Reader", "Group", "sg-azure-readers"),
                A(SubProd, $"{prodScope}/resourceGroups/rg-web", "Contributor", "ServicePrincipal", "sp-github-deploy-prod"),
                A(SubProd, $"{prodScope}/resourceGroups/rg-data", "Storage Blob Data Contributor", "ServicePrincipal", "mi-func-contoso-orders"),
                A(SubProd, $"{prodScope}/resourceGroups/rg-security", "Key Vault Secrets User", "ServicePrincipal", "mi-app-contoso-portal"),
                A(SubProd, $"{prodScope}/resourceGroups/rg-monitoring", "Monitoring Reader", "Group", "sg-noc"),
                A(SubDev, devScope, "Owner", "User", "alex.morgan@contoso.com"),
                A(SubDev, devScope, "Owner", "User", "sam.patel@contoso.com"),
                A(SubDev, devScope, "Owner", "User", "jordan.lee@contoso.com"),
                A(SubDev, devScope, "Owner", "User", "taylor.kim@contoso.com"),
                A(SubDev, devScope, "Owner", "ServicePrincipal", "sp-terraform-dev"),
                A(SubDev, devScope, "Owner", "User", "chris.evans_partner.com#EXT#@contoso.onmicrosoft.com", guest: true),
                A(SubDev, devScope, "Contributor", "User", "dev-team-lead@contoso.com"),
                A(SubDev, devScope, "Contributor", "User", "contractor-01@contoso.com"),
                A(SubDev, devScope, "User Access Administrator", "User", "alex.morgan@contoso.com"),
                A(SubDev, devScope, "Reader", "User", "finance@contoso.com"),
                A(SubDev, devScope, "Contributor", "", "(deleted principal)", orphaned: true),
                A(SubDev, devScope, "Reader", "", "(deleted principal)", orphaned: true),
                A(SubDev, $"{devScope}/resourceGroups/rg-dev", "Contributor", "Group", "sg-dev-team"),
            ],
            CustomRoles =
            [
                new() { Id = $"{prodScope}/providers/Microsoft.Authorization/roleDefinitions/custom-1", Name = "Contoso VM Operator", SubscriptionId = SubProd, Actions = ["Microsoft.Compute/virtualMachines/start/action", "Microsoft.Compute/virtualMachines/restart/action", "Microsoft.Compute/virtualMachines/read"], AssignableScopeCount = 1 },
                new() { Id = $"{devScope}/providers/Microsoft.Authorization/roleDefinitions/custom-2", Name = "Dev Super User", SubscriptionId = SubDev, Actions = ["*"], AssignableScopeCount = 1 },
            ],
            UserAssignedIdentities =
            [
                new() { Id = $"{Rg(SubProd, "rg-web")}/Microsoft.ManagedIdentity/userAssignedIdentities/id-contoso-web", Name = "id-contoso-web", ResourceGroup = "rg-web", SubscriptionId = SubProd, Location = "uksouth" },
            ],
        };
        return r;
    }
}
