using RateMyAzureSubscriptions.Models;

namespace RateMyAzureSubscriptions.Services.Assessment;

/// <summary>
/// Storage (100): access control 30 · network security 20 · data protection 25 · lifecycle &amp; cost 15 · encryption &amp; configuration 10.
/// Caps: any account allowing anonymous blob access → max C · any account accepting HTTP or TLS below 1.2 → max C.
/// </summary>
internal static class StorageAssessor
{
    public const string AccessCategory = "Access control";
    public const string NetworkCategory = "Network security";
    public const string ProtectionCategory = "Data protection";
    public const string LifecycleCategory = "Lifecycle & cost";
    public const string ConfigCategory = "Encryption & configuration";

    public static AreaRating Assess(AuditScanResult scan, FindingSink findings)
    {
        var area = AuditArea.Storage;
        var accounts = scan.StorageAccounts;
        if (accounts.Count == 0)
            return RatingBuilder.NotAssessed(area, "No storage accounts in the scanned subscriptions.");

        var b = new RatingBuilder(area);
        var n = accounts.Count;

        // ── 1. Access control (30) ───────────────────────────────────────────
        var access = b.Category(AccessCategory, 30);
        var noPublicBlob = accounts.Count(a => a.AllowBlobPublicAccess == false);
        b.Check(access, 10, noPublicBlob, n,
            $"{noPublicBlob} of {n} account(s) disallow anonymous blob access.",
            $"Disallow blob public access on {n - noPublicBlob} account(s).", "publicblob");
        if (noPublicBlob < n)
            b.Cap("publicblob", "C", "At least one storage account allows anonymous (public) blob access.");
        foreach (var a in accounts.Where(a => a.AllowBlobPublicAccess != false))
            findings.Add(area, "High", "Blob public access allowed", $"Storage account '{a.Name}' allows anonymous public access to blobs{(a.AllowBlobPublicAccess is null ? " (setting not explicitly disabled)" : "")}.", a);

        var httpsOnly = accounts.Count(a => a.SupportsHttpsTrafficOnly);
        b.Check(access, 8, httpsOnly, n,
            $"{httpsOnly} of {n} account(s) require secure transfer (HTTPS).",
            $"Require HTTPS on {n - httpsOnly} account(s).", "transport");
        var tlsOk = accounts.Count(a => a.TlsOk);
        b.Check(access, 7, tlsOk, n,
            $"{tlsOk} of {n} account(s) require TLS 1.2 or later.",
            $"Set minimum TLS 1.2 on {n - tlsOk} account(s).", "transport");
        if (httpsOnly < n || tlsOk < n)
            b.Cap("transport", "C", "At least one storage account accepts HTTP or TLS below 1.2.");
        foreach (var a in accounts.Where(a => !a.SupportsHttpsTrafficOnly))
            findings.Add(area, "High", "HTTP allowed on storage", $"Storage account '{a.Name}' does not require secure transfer.", a);
        foreach (var a in accounts.Where(a => !a.TlsOk))
            findings.Add(area, "Medium", "Outdated TLS on storage", $"Storage account '{a.Name}' allows {(string.IsNullOrEmpty(a.MinimumTlsVersion) ? "TLS 1.0" : a.MinimumTlsVersion.Replace('_', '.'))}.", a);

        var noSharedKey = accounts.Count(a => a.AllowSharedKeyAccess == false);
        b.Check(access, 5, noSharedKey, n,
            $"{noSharedKey} of {n} account(s) have shared key access disabled.",
            $"Move {n - noSharedKey} account(s) to Entra authorization and disable shared keys.");
        foreach (var a in accounts.Where(a => a.AllowSharedKeyAccess != false))
            findings.Add(area, "Low", "Shared key access enabled", $"Storage account '{a.Name}' allows authorization with the account keys.", a);

        // ── 2. Network security (20) ─────────────────────────────────────────
        var net = b.Category(NetworkCategory, 20);
        var restricted = accounts.Count(a => a.PublicNetworkRestricted);
        b.Check(net, 12, restricted, n,
            $"{restricted} of {n} account(s) restrict public network access (default deny or disabled).",
            $"Set the network default action to Deny on {n - restricted} account(s).");
        foreach (var a in accounts.Where(a => !a.PublicNetworkRestricted))
            findings.Add(area, "Medium", "Storage public network access", $"Storage account '{a.Name}' accepts traffic from all networks.", a);

        var withPe = accounts.Count(a => a.HasPrivateEndpoint);
        b.Check(net, 8, withPe, n,
            $"{withPe} of {n} account(s) have a private endpoint.",
            $"Add private endpoints to {n - withPe} account(s).");
        foreach (var a in accounts.Where(a => !a.HasPrivateEndpoint))
            findings.Add(area, "Low", "No private endpoint", $"Storage account '{a.Name}' has no private endpoint.", a);

        // ── 3. Data protection (25) ──────────────────────────────────────────
        var prot = b.Category(ProtectionCategory, 25);
        var sdKnown = accounts.Where(a => a.BlobSoftDeleteEnabled is not null).ToList();
        if (sdKnown.Count == 0)
        {
            prot.Earned += 9;
            prot.Details.Add("Blob service properties could not be read — half points awarded for soft delete and versioning.");
        }
        else
        {
            b.Check(prot, 8, sdKnown.Count(a => a.BlobSoftDeleteEnabled == true), sdKnown.Count,
                $"{sdKnown.Count(a => a.BlobSoftDeleteEnabled == true)} of {sdKnown.Count} account(s) have blob soft delete.",
                "Enable blob soft delete on every account.");
            foreach (var a in sdKnown.Where(a => a.BlobSoftDeleteEnabled == false))
                findings.Add(area, "Medium", "Blob soft delete off", $"Storage account '{a.Name}' has blob soft delete disabled.", a);

            b.Check(prot, 5, sdKnown.Count(a => a.ContainerSoftDeleteEnabled == true), sdKnown.Count,
                $"{sdKnown.Count(a => a.ContainerSoftDeleteEnabled == true)} of {sdKnown.Count} account(s) have container soft delete.",
                "Enable container soft delete on every account.");
            foreach (var a in sdKnown.Where(a => a.ContainerSoftDeleteEnabled != true))
                findings.Add(area, "Low", "Container soft delete off", $"Storage account '{a.Name}' has container soft delete disabled.", a);

            b.Check(prot, 5, sdKnown.Count(a => a.VersioningEnabled == true), sdKnown.Count,
                $"{sdKnown.Count(a => a.VersioningEnabled == true)} of {sdKnown.Count} account(s) have blob versioning.",
                "Enable blob versioning where overwrites must be recoverable.");
            foreach (var a in sdKnown.Where(a => a.VersioningEnabled != true && !a.IsHierarchicalNamespace))
                findings.Add(area, "Low", "Versioning off", $"Storage account '{a.Name}' has blob versioning disabled.", a);
        }

        var redundant = accounts.Count(a => a.IsRedundant);
        b.Check(prot, 7, redundant, n,
            $"{redundant} of {n} account(s) use zone- or geo-redundant storage.",
            $"Move {n - redundant} locally-redundant account(s) holding production data to ZRS or GRS.");
        foreach (var a in accounts.Where(a => !a.IsRedundant))
            findings.Add(area, "Low", "Locally redundant storage", $"Storage account '{a.Name}' uses {a.SkuName} (single-datacentre redundancy).", a);

        // ── 4. Lifecycle & cost (15) ─────────────────────────────────────────
        var life = b.Category(LifecycleCategory, 15);
        var lcKnown = accounts.Where(a => a.HasLifecyclePolicy is not null).ToList();
        if (lcKnown.Count == 0)
        {
            life.Earned += 4;
            life.Details.Add("Lifecycle policies could not be read — half points awarded.");
        }
        else
        {
            b.Check(life, 8, lcKnown.Count(a => a.HasLifecyclePolicy == true), lcKnown.Count,
                $"{lcKnown.Count(a => a.HasLifecyclePolicy == true)} of {lcKnown.Count} account(s) have a lifecycle management policy.",
                "Add lifecycle management policies to tier and expire old data.");
            foreach (var a in lcKnown.Where(a => a.HasLifecyclePolicy == false && !a.IsV1))
                findings.Add(area, "Low", "No lifecycle policy", $"Storage account '{a.Name}' has no lifecycle management policy.", a);
        }
        var v2 = accounts.Count(a => !a.IsV1);
        b.Check(life, 7, v2, n,
            $"{v2} of {n} account(s) are general-purpose v2.",
            $"Upgrade {n - v2} v1/Blob account(s) to StorageV2.");
        foreach (var a in accounts.Where(a => a.IsV1))
            findings.Add(area, "Low", "Storage v1 account", $"Storage account '{a.Name}' is a {a.Kind} account without access tiers or lifecycle management.", a);

        // ── 5. Encryption & configuration (10) ───────────────────────────────
        var cfg = b.Category(ConfigCategory, 10);
        var infra = accounts.Count(a => a.InfrastructureEncryption);
        b.Check(cfg, 4, infra, n,
            $"{infra} of {n} account(s) have infrastructure (double) encryption.",
            "Use infrastructure encryption for new accounts holding regulated data.");
        foreach (var a in accounts.Where(a => !a.InfrastructureEncryption))
            findings.Add(area, "Low", "Infrastructure encryption off", $"Storage account '{a.Name}' is encrypted once (no infrastructure encryption).", a);

        var noXTenant = accounts.Count(a => a.AllowCrossTenantReplication == false);
        b.Check(cfg, 3, noXTenant, n,
            $"{noXTenant} of {n} account(s) disallow cross-tenant replication.",
            $"Disallow cross-tenant replication on {n - noXTenant} account(s).");
        foreach (var a in accounts.Where(a => a.AllowCrossTenantReplication != false))
            findings.Add(area, "Low", "Cross-tenant replication allowed", $"Storage account '{a.Name}' allows object replication to other tenants.", a);

        var oauth = accounts.Count(a => a.DefaultToOAuthAuthentication == true);
        b.Check(cfg, 3, oauth, n,
            $"{oauth} of {n} account(s) default to Entra authorization in the portal.",
            $"Default {n - oauth} account(s) to Entra authorization.");
        foreach (var a in accounts.Where(a => a.DefaultToOAuthAuthentication != true))
            findings.Add(area, "Low", "Shared key default in portal", $"Storage account '{a.Name}' defaults tools to account-key authorization.", a);

        return b.Build(n, $"{n} storage account{(n == 1 ? "" : "s")}");
    }
}
