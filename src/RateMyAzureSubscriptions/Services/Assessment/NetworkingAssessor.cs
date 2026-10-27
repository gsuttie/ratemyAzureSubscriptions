using RateMyAzureSubscriptions.Models;

namespace RateMyAzureSubscriptions.Services.Assessment;

/// <summary>
/// Networking (100): segmentation 25 · exposure 25 · threat protection 15 · monitoring 15 · hygiene &amp; cost 20.
/// Caps: management port open to the Internet → max D · any workload subnet without an NSG → max B.
/// </summary>
internal static class NetworkingAssessor
{
    public const string SegmentationCategory = "Segmentation & NSG coverage";
    public const string ExposureCategory = "Internet exposure";
    public const string ProtectionCategory = "Threat protection";
    public const string MonitoringCategory = "Network monitoring";
    public const string HygieneCategory = "Hygiene & cost";

    private static readonly string[] PaasTypes = ["blob", "file", "queue", "table", "dfs", "vault", "sqlServer", "sites"];

    public static AreaRating Assess(AuditScanResult scan, FindingSink findings)
    {
        var area = AuditArea.Networking;
        var vnets = scan.VirtualNetworks;
        var nsgs = scan.NetworkSecurityGroups;
        var pips = scan.PublicIps;

        if (vnets.Count == 0 && nsgs.Count == 0 && pips.Count == 0 && scan.StorageAccounts.Count == 0 && scan.KeyVaults.Count == 0)
            return RatingBuilder.NotAssessed(area, "No virtual networks, NSGs, public IPs or PaaS endpoints in the scanned subscriptions.");

        var b = new RatingBuilder(area);

        // ── 1. Segmentation & NSG coverage (25) ──────────────────────────────
        var seg = b.Category(SegmentationCategory, 25);
        var subnets = vnets.SelectMany(v => v.Subnets.Select(s => (VNet: v, Subnet: s))).Where(x => !x.Subnet.IsPlatformSubnet && !x.Subnet.HasDelegation).ToList();
        var withNsg = subnets.Count(x => x.Subnet.NsgId is not null);
        b.Check(seg, 25, withNsg, subnets.Count,
            subnets.Count == 0 ? "No workload subnets to assess." : $"{withNsg} of {subnets.Count} workload subnet(s) have a network security group.",
            $"Associate an NSG with the {subnets.Count - withNsg} subnet(s) without one.", "nonsg");
        if (withNsg < subnets.Count)
            b.Cap("nonsg", "B", $"{subnets.Count - withNsg} workload subnet(s) have no network security group.");
        foreach (var (vnet, s) in subnets.Where(x => x.Subnet.NsgId is null))
            findings.Add(area, "Medium", "Subnet without NSG", $"Subnet '{s.Name}' ({s.AddressPrefix}) in VNet '{vnet.Name}' has no network security group.", s.Name, s.Id, vnet.ResourceGroup, vnet.SubscriptionId);

        // ── 2. Internet exposure (25) ────────────────────────────────────────
        var exp = b.Category(ExposureCategory, 25);
        var risky = nsgs.Where(n => n.RiskyRules.Count > 0).ToList();
        b.Check(exp, 10, nsgs.Count - risky.Count, nsgs.Count,
            nsgs.Count == 0 ? "No NSGs to assess." : risky.Count == 0 ? "No NSG allows management ports (SSH, RDP, WinRM, SQL) from the Internet." : $"{risky.Count} of {nsgs.Count} NSG(s) allow management ports from the Internet.",
            $"Remove or restrict the Internet-facing management-port rules on {risky.Count} NSG(s).", "openports");
        if (risky.Count > 0)
            b.Cap("openports", "D", "Management ports are reachable from the Internet.");
        foreach (var n in risky)
            foreach (var r in n.RiskyRules)
                findings.Add(area, "High", "Management port open to Internet",
                    $"NSG '{n.Name}' rule '{r.Name}' (priority {r.Priority}) allows {string.Join(",", r.DestinationPorts)} from {string.Join(",", r.Sources)}.", n);

        var vms = scan.VirtualMachines;
        var withoutPip = vms.Count(v => !v.HasPublicIp);
        b.Check(exp, 8, withoutPip, vms.Count,
            vms.Count == 0 ? "No VMs to assess." : $"{withoutPip} of {vms.Count} VM(s) have no public IP attached directly.",
            $"Remove the direct public IPs from {vms.Count - withoutPip} VM(s) and use Bastion, VPN or a load balancer.");
        foreach (var v in vms.Where(v => v.HasPublicIp))
            findings.Add(area, "Medium", "VM with public IP", $"VM '{v.Name}' has a public IP address attached directly to its network interface.", v);

        var paas = scan.StorageAccounts.Select(s => (Name: s.Name, Restricted: s.PublicNetworkRestricted || s.HasPrivateEndpoint, Res: (ResourceBase)s, Type: "Storage account"))
            .Concat(scan.KeyVaults.Select(k => (Name: k.Name, Restricted: k.PublicNetworkRestricted, Res: (ResourceBase)k, Type: "Key Vault")))
            .Concat(scan.SqlServers.Select(q => (Name: q.Name, Restricted: q.PublicNetworkRestricted, Res: (ResourceBase)q, Type: "SQL server")))
            .ToList();
        var paasRestricted = paas.Count(p => p.Restricted);
        b.Check(exp, 7, paasRestricted, paas.Count,
            paas.Count == 0 ? "No PaaS endpoints to assess." : $"{paasRestricted} of {paas.Count} PaaS endpoint(s) (storage, Key Vault, SQL) restrict public network access.",
            $"Disable public network access (or restrict the firewall) on {paas.Count - paasRestricted} PaaS endpoint(s).");
        foreach (var p in paas.Where(p => !p.Restricted))
            findings.Add(area, "Medium", "PaaS public network access", $"{p.Type} '{p.Name}' is reachable from any public network.", p.Res);

        // ── 3. Threat protection (15) ────────────────────────────────────────
        var prot = b.Category(ProtectionCategory, 15);
        var internetVnets = vnets.Where(v => pips.Any(p => p.IsAttached) || scan.VirtualMachines.Any(vm => vm.HasPublicIp)).ToList();
        var ddos = internetVnets.Count(v => v.DdosProtectionEnabled);
        b.Check(prot, 8, ddos, internetVnets.Count,
            internetVnets.Count == 0 ? "No Internet-facing virtual networks to assess." : $"{ddos} of {internetVnets.Count} virtual network(s) with public endpoints have DDoS protection.",
            $"Enable DDoS Network Protection on {internetVnets.Count - ddos} Internet-facing virtual network(s).");
        foreach (var v in internetVnets.Where(v => !v.DdosProtectionEnabled))
            findings.Add(area, "Low", "DDoS protection off", $"VNet '{v.Name}' hosts public endpoints but has no DDoS protection plan.", v);

        if (vms.Count == 0)
        {
            prot.Earned += 7;
            prot.Details.Add("No VMs, so no administrative access path to assess.");
        }
        else if (scan.BastionCount > 0)
        {
            prot.Earned += 7;
            prot.Details.Add($"Azure Bastion is deployed ({scan.BastionCount}).");
        }
        else
        {
            prot.Details.Add("No Azure Bastion host — VM administration relies on public IPs or VPN.");
            b.Improve("Deploy Azure Bastion for administrative access to VMs.", 7);
            findings.Add(area, "Low", "No Azure Bastion", $"No Azure Bastion host exists for administering the {vms.Count} VM(s).", "Subscriptions in scope");
        }

        // ── 4. Network monitoring (15) ───────────────────────────────────────
        var mon = b.Category(MonitoringCategory, 15);
        var regions = vnets.Select(v => (v.Location, v.SubscriptionId)).Distinct().ToList();
        var watched = regions.Count(r => scan.NetworkWatchers.Any(w => w.Location.Equals(r.Location, StringComparison.OrdinalIgnoreCase) && w.SubscriptionId.Equals(r.SubscriptionId, StringComparison.OrdinalIgnoreCase)));
        b.Check(mon, 8, watched, regions.Count,
            regions.Count == 0 ? "No virtual networks to assess." : $"Network Watcher is enabled in {watched} of {regions.Count} region/subscription pair(s) with virtual networks.",
            $"Enable Network Watcher in the {regions.Count - watched} region(s) where it is missing.");
        foreach (var r in regions.Where(r => !scan.NetworkWatchers.Any(w => w.Location.Equals(r.Location, StringComparison.OrdinalIgnoreCase) && w.SubscriptionId.Equals(r.SubscriptionId, StringComparison.OrdinalIgnoreCase))))
            findings.Add(area, "Low", "Network Watcher missing", $"Network Watcher is not enabled in {r.Location}, which hosts virtual networks.", r.Location, "", "", r.SubscriptionId);

        var flowTargets = vnets.Select(v => v.Id).Concat(nsgs.Where(n => !n.IsOrphaned).Select(n => n.Id)).ToList();
        var flowCovered = vnets.Count(v => scan.FlowLogs.Any(f => f.Enabled && f.TargetResourceId.Equals(v.Id, StringComparison.OrdinalIgnoreCase))
            || v.Subnets.Any(s => s.NsgId is not null && scan.FlowLogs.Any(f => f.Enabled && f.TargetResourceId.Equals(s.NsgId, StringComparison.OrdinalIgnoreCase))));
        b.Check(mon, 7, flowCovered, vnets.Count,
            vnets.Count == 0 ? "No virtual networks to assess." : $"{flowCovered} of {vnets.Count} virtual network(s) have flow logs (VNet or NSG) enabled.",
            $"Enable flow logs on the {vnets.Count - flowCovered} virtual network(s) without them.");
        foreach (var v in vnets.Where(v => !scan.FlowLogs.Any(f => f.Enabled && (f.TargetResourceId.Equals(v.Id, StringComparison.OrdinalIgnoreCase) || v.Subnets.Any(s => s.NsgId is not null && f.TargetResourceId.Equals(s.NsgId, StringComparison.OrdinalIgnoreCase))))))
            findings.Add(area, "Low", "No flow logs", $"VNet '{v.Name}' has no flow logs, so traffic patterns cannot be analysed.", v);

        // ── 5. Hygiene & cost (20) ───────────────────────────────────────────
        var hyg = b.Category(HygieneCategory, 20);
        var orphanPips = pips.Where(p => !p.IsAttached).ToList();
        b.Check(hyg, 7, pips.Count - orphanPips.Count, pips.Count,
            pips.Count == 0 ? "No public IPs to assess." : orphanPips.Count == 0 ? "Every public IP is attached." : $"{orphanPips.Count} of {pips.Count} public IP(s) are unattached.",
            $"Delete the {orphanPips.Count} unattached public IP(s).");
        foreach (var p in orphanPips)
            findings.Add(area, "Low", "Unattached public IP", $"Public IP '{p.Name}' ({(string.IsNullOrEmpty(p.IpAddress) ? "no address" : p.IpAddress)}, {p.Sku}) is not attached to anything.", p);

        var orphanNsgs = nsgs.Where(n => n.IsOrphaned).ToList();
        b.Check(hyg, 6, nsgs.Count - orphanNsgs.Count, nsgs.Count,
            nsgs.Count == 0 ? "No NSGs to assess." : orphanNsgs.Count == 0 ? "Every NSG is associated with a subnet or NIC." : $"{orphanNsgs.Count} of {nsgs.Count} NSG(s) are not associated with anything.",
            $"Remove the {orphanNsgs.Count} orphaned NSG(s).");
        foreach (var n in orphanNsgs)
            findings.Add(area, "Low", "Orphaned NSG", $"NSG '{n.Name}' is not associated with any subnet or network interface.", n);

        var peGroups = scan.PrivateEndpoints.Select(pe => pe.GroupId).Where(g => !string.IsNullOrEmpty(g)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var zonesOk = peGroups.Count(g => scan.PrivateDnsZones.Any(z => z.Name.Contains("privatelink", StringComparison.OrdinalIgnoreCase) && ZoneMatches(z.Name, g)));
        b.Check(hyg, 7, zonesOk, peGroups.Count,
            peGroups.Count == 0 ? "No private endpoints to assess." : $"{zonesOk} of {peGroups.Count} private endpoint service type(s) have a matching privatelink DNS zone.",
            $"Create the privatelink DNS zones for {peGroups.Count - zonesOk} private endpoint service type(s).");
        foreach (var g in peGroups.Where(g => !scan.PrivateDnsZones.Any(z => ZoneMatches(z.Name, g))))
            findings.Add(area, "Medium", "Private DNS zone missing", $"Private endpoints for '{g}' exist but no matching privatelink private DNS zone was found.", g);

        var parts = new List<string>();
        if (vnets.Count > 0) parts.Add($"{vnets.Count} VNet{(vnets.Count == 1 ? "" : "s")}");
        if (subnets.Count > 0) parts.Add($"{subnets.Count} subnet{(subnets.Count == 1 ? "" : "s")}");
        if (nsgs.Count > 0) parts.Add($"{nsgs.Count} NSG{(nsgs.Count == 1 ? "" : "s")}");
        if (pips.Count > 0) parts.Add($"{pips.Count} public IP{(pips.Count == 1 ? "" : "s")}");
        if (scan.PrivateEndpoints.Count > 0) parts.Add($"{scan.PrivateEndpoints.Count} private endpoint{(scan.PrivateEndpoints.Count == 1 ? "" : "s")}");
        return b.Build(vnets.Count + nsgs.Count + pips.Count + scan.PrivateEndpoints.Count, string.Join(", ", parts));
    }

    /// <summary>privatelink.blob.core.windows.net ↔ "blob", privatelink.vaultcore.azure.net ↔ "vault", privatelink.database.windows.net ↔ "sqlServer".</summary>
    internal static bool ZoneMatches(string zoneName, string groupId)
    {
        var z = zoneName.ToLowerInvariant();
        var g = groupId.ToLowerInvariant();
        return g switch
        {
            "vault" => z.Contains("vaultcore"),
            "sqlserver" => z.Contains("database.windows.net"),
            "sites" => z.Contains("azurewebsites"),
            "namespace" => z.Contains("servicebus"),
            "registry" => z.Contains("azurecr"),
            "sql" => z.Contains("documents.azure.com"),
            "mysqlserver" => z.Contains("mysql"),
            "postgresqlserver" => z.Contains("postgres"),
            "redis" or "rediscache" => z.Contains("redis"),
            "management" or "cluster" => z.Contains("azmk8s"),
            _ => z.Contains($"privatelink.{g}.") || z.Contains(g),
        };
    }
}
