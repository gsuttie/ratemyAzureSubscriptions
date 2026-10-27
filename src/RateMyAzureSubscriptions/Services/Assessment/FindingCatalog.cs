using RateMyAzureSubscriptions.Models;

namespace RateMyAzureSubscriptions.Services.Assessment;

/// <summary>
/// Remediation guidance per finding category: the fix in words, the effort it takes, and (where a safe
/// one-liner exists) an Azure CLI snippet. The assessors only name the category; everything the
/// customer reads about "how to fix it" lives here.
/// </summary>
public static class FindingCatalog
{
    public sealed record Entry(string Fix, string Effort, Func<AuditFinding, string?>? Script = null);

    private static string Sub(AuditFinding f) => string.IsNullOrEmpty(f.SubscriptionId) ? "<subscription-id>" : f.SubscriptionId;
    private static string Rg(AuditFinding f) => string.IsNullOrEmpty(f.ResourceGroup) ? "<resource-group>" : f.ResourceGroup;
    private static string Header(AuditFinding f, string what) =>
        $"# {what}\n# Review before running. RateMyAzureSubscriptions never changes Azure itself.\naz account set --subscription \"{Sub(f)}\"\n";

    public static readonly IReadOnlyDictionary<string, Entry> Entries = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase)
    {
        // ── Compute ──────────────────────────────────────────────────────────
        ["VM not backed up"] = new("Enable Azure Backup for the VM with a Recovery Services vault and a policy that matches its recovery objectives (daily backups, 30+ days retention for production).", "Low",
            f => Header(f, $"Enable backup for VM '{f.ResourceName}'") +
                 $"az backup protection enable-for-vm --resource-group \"{Rg(f)}\" --vm \"{f.ResourceName}\" --vault-name \"<recovery-services-vault>\" --policy-name \"DefaultPolicy\""),
        ["No availability zone or set"] = new("Deploy production VMs across availability zones (or at least an availability set) so a single host or datacentre failure does not take the workload down. Zones require a redeploy; plan it with a maintenance window.", "High"),
        ["Unmanaged disks"] = new("Convert the VM to managed disks. Managed disks are required for availability zones, backup features and most newer VM sizes, and remove the storage-account single point of failure.", "Medium",
            f => Header(f, $"Convert VM '{f.ResourceName}' to managed disks (VM is deallocated during conversion)") +
                 $"az vm deallocate --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\"\naz vm convert --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\"\naz vm start --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\""),
        ["Boot diagnostics off"] = new("Enable boot diagnostics (managed storage) so boot failures and the serial console are available when the VM will not start.", "Low",
            f => Header(f, $"Enable boot diagnostics on VM '{f.ResourceName}'") +
                 $"az vm boot-diagnostics enable --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\""),
        ["Stopped VM still billed"] = new("A VM that is stopped from inside the OS keeps its compute allocation and is billed in full. Deallocate it from Azure (or delete it if it is no longer needed).", "Low",
            f => Header(f, $"Deallocate VM '{f.ResourceName}' so compute is no longer billed") +
                 $"az vm deallocate --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\""),
        ["Unattached disk"] = new("The disk is not attached to any VM but is still billed. Confirm it is not needed (snapshot it if unsure), then delete it.", "Low",
            f => Header(f, $"Delete unattached disk '{f.ResourceName}' (take a snapshot first if in doubt)") +
                 $"az snapshot create --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}-snap\" --source \"{f.ResourceName}\"\naz disk delete --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --yes"),
        ["Previous-generation VM size"] = new("Resize to a current-generation series (for example D-series v5/v6 or B-series for burstable workloads) — typically cheaper and faster for the same vCPU/memory. Resizing restarts the VM.", "Medium",
            f => Header(f, $"Resize VM '{f.ResourceName}' to a current-generation size") +
                 $"az vm list-vm-resize-options --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --output table\naz vm resize --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --size \"Standard_D2s_v5\""),
        ["No Azure Hybrid Benefit"] = new("If the organisation owns Windows Server licences with Software Assurance, enable Azure Hybrid Benefit on the VM to stop paying for the Windows licence in the hourly rate (up to 40% saving).", "Low",
            f => Header(f, $"Enable Azure Hybrid Benefit on VM '{f.ResourceName}'") +
                 $"az vm update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --license-type Windows_Server"),
        ["HTTPS only off"] = new("Enforce HTTPS-only so plain HTTP requests are redirected and no credentials or tokens travel unencrypted.", "Low",
            f => Header(f, $"Enforce HTTPS on '{f.ResourceName}'") +
                 $"az webapp update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --https-only true"),
        ["Outdated TLS on web app"] = new("Set the minimum inbound TLS version to 1.2 so clients cannot negotiate TLS 1.0/1.1, which have known weaknesses and fail most compliance baselines.", "Low",
            f => Header(f, $"Require TLS 1.2 on '{f.ResourceName}'") +
                 $"az webapp config set --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --min-tls-version 1.2"),
        ["FTP enabled on web app"] = new("Disable FTP (or allow FTPS only). Plain FTP sends deployment credentials in clear text.", "Low",
            f => Header(f, $"Disable FTP on '{f.ResourceName}'") +
                 $"az webapp config set --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --ftps-state Disabled"),
        ["No managed identity"] = new("Assign a managed identity and use it (instead of connection strings or client secrets in app settings) to reach Key Vault, Storage, SQL and other Azure services.", "Medium",
            f => Header(f, $"Assign a system-assigned managed identity to '{f.ResourceName}'") +
                 $"az webapp identity assign --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\""),
        ["Empty App Service plan"] = new("The plan hosts no apps but is billed per instance. Delete it, or move apps onto it and delete another plan.", "Low",
            f => Header(f, $"Delete empty App Service plan '{f.ResourceName}'") +
                 $"az appservice plan delete --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --yes"),
        ["Free or Shared plan"] = new("Free and Shared tiers have no SLA, no custom-domain TLS and limited CPU minutes. Move anything that matters to Basic or Standard (Premium v3 for production).", "Medium",
            f => Header(f, $"Upgrade App Service plan '{f.ResourceName}'") +
                 $"az appservice plan update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --sku S1"),
        ["Single-instance plan"] = new("Run at least two instances (and zone redundancy on Premium v3) so a single instance restart or host failure does not cause an outage.", "Low",
            f => Header(f, $"Scale App Service plan '{f.ResourceName}' to two instances") +
                 $"az appservice plan update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --number-of-workers 2"),
        ["Always On disabled"] = new("Enable Always On so the app is not unloaded after idle periods, avoiding cold-start latency and missed timer jobs.", "Low",
            f => Header(f, $"Enable Always On for '{f.ResourceName}'") +
                 $"az webapp config set --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --always-on true"),

        // ── Networking ───────────────────────────────────────────────────────
        ["Subnet without NSG"] = new("Associate a network security group with the subnet so traffic is filtered at the boundary; start from deny-all inbound and add only the required rules.", "Low",
            f => Header(f, $"Attach an NSG to subnet '{f.ResourceName}'") +
                 $"az network vnet subnet update --resource-group \"{Rg(f)}\" --vnet-name \"<vnet-name>\" --name \"{f.ResourceName}\" --network-security-group \"<nsg-name>\""),
        ["Management port open to Internet"] = new("Remove the rule or restrict its source to known addresses. Use Azure Bastion, a VPN or just-in-time VM access for administrative connections instead of exposing SSH/RDP/SQL to the Internet.", "Low",
            f => Header(f, $"Remove the Internet-facing rule on NSG '{f.ResourceName}'") +
                 $"az network nsg rule delete --resource-group \"{Rg(f)}\" --nsg-name \"{f.ResourceName}\" --name \"<rule-name>\""),
        ["VM with public IP"] = new("Remove the public IP from the NIC and reach the VM through Azure Bastion, a VPN/ExpressRoute or a load balancer / application gateway in front of it.", "Medium",
            f => Header(f, $"Detach the public IP from VM '{f.ResourceName}'") +
                 $"az network nic ip-config update --resource-group \"{Rg(f)}\" --nic-name \"<nic-name>\" --name ipconfig1 --remove publicIpAddress"),
        ["PaaS public network access"] = new("Disable public network access on the service and connect through a private endpoint (or at minimum restrict the firewall to the required VNets/IP ranges).", "Medium"),
        ["DDoS protection off"] = new("Enable DDoS Network Protection (or IP Protection on the public IPs) for virtual networks that host Internet-facing endpoints.", "Low",
            f => Header(f, $"Enable DDoS protection on VNet '{f.ResourceName}'") +
                 $"az network vnet update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --ddos-protection true --ddos-protection-plan \"<ddos-plan-id>\""),
        ["No Azure Bastion"] = new("Deploy Azure Bastion (Developer or Basic SKU for small estates) so administrators reach VMs over the portal/CLI without public IPs or open management ports.", "Medium"),
        ["Network Watcher missing"] = new("Enable Network Watcher in every region that hosts a virtual network so connection troubleshooting, packet capture and flow logs are available.", "Low",
            f => Header(f, $"Enable Network Watcher in {f.ResourceName}") +
                 $"az network watcher configure --locations {f.ResourceName} --enabled true"),
        ["No flow logs"] = new("Enable virtual network flow logs (sent to Log Analytics with Traffic Analytics) so lateral movement and unexpected flows are visible.", "Medium"),
        ["Unattached public IP"] = new("The public IP is not attached to anything but is still billed (Standard SKU). Delete it if it is not reserved for a known purpose.", "Low",
            f => Header(f, $"Delete unattached public IP '{f.ResourceName}'") +
                 $"az network public-ip delete --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\""),
        ["Orphaned NSG"] = new("The NSG is not associated with any subnet or NIC. Remove it to keep the rule base tidy, or associate it where it is meant to apply.", "Low",
            f => Header(f, $"Delete orphaned NSG '{f.ResourceName}'") +
                 $"az network nsg delete --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\""),
        ["Private DNS zone missing"] = new("Create the privatelink.* private DNS zone for the service type, link it to the VNets and let the private endpoint register its record so clients resolve the private address.", "Medium"),

        // ── Security ─────────────────────────────────────────────────────────
        ["Defender plan off"] = new("Enable the Microsoft Defender for Cloud plan for this resource type so threat detection, vulnerability assessment and hardening recommendations are produced.", "Low",
            f => Header(f, $"Enable the Defender plan '{f.ResourceName}'") +
                 $"az security pricing create --name \"{f.ResourceName}\" --tier Standard"),
        ["No security contact"] = new("Configure a security contact email (and alert notifications for High severity) so Defender for Cloud alerts reach someone.", "Low",
            f => Header(f, "Set the Defender for Cloud security contact") +
                 "az security contact create --name default --emails \"security@example.com\" --alert-notifications \"{\\\"state\\\":\\\"On\\\",\\\"minimalSeverity\\\":\\\"High\\\"}\" --notifications-by-role \"{\\\"state\\\":\\\"On\\\",\\\"roles\\\":[\\\"Owner\\\"]}\""),
        ["Low secure score"] = new("Work through the Defender for Cloud recommendations, highest impact first; the secure score shows how far the estate is from Microsoft's baseline.", "High"),
        ["Unhealthy recommendations"] = new("Review the High severity Defender for Cloud recommendations in the portal and remediate or create an exemption with a documented reason.", "Medium"),
        ["Security benchmark not assigned"] = new("Assign the Microsoft cloud security benchmark initiative at subscription (or management group) scope so compliance is continuously measured.", "Low",
            f => Header(f, "Assign the Microsoft cloud security benchmark") +
                 $"az policy assignment create --name mcsb --display-name \"Microsoft cloud security benchmark\" --policy-set-definition 1f3afdf9-d0c9-4c3d-847f-89da613e70a8 --scope \"/subscriptions/{Sub(f)}\""),
        ["No policy assignments"] = new("Assign guardrail policies (allowed locations, required tags, deny public IPs, audit missing diagnostics) so configuration drift is prevented rather than discovered.", "Medium"),
        ["Key Vault soft delete off"] = new("Enable soft delete so deleted keys, secrets and certificates can be recovered within the retention period.", "Low",
            f => Header(f, $"Enable soft delete on Key Vault '{f.ResourceName}'") +
                 $"az keyvault update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --enable-soft-delete true"),
        ["Key Vault purge protection off"] = new("Enable purge protection so a compromised or mistaken identity cannot permanently destroy keys during the soft-delete window. This cannot be undone.", "Low",
            f => Header(f, $"Enable purge protection on Key Vault '{f.ResourceName}'") +
                 $"az keyvault update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --enable-purge-protection true"),
        ["Key Vault access policies"] = new("Migrate the vault to the Azure RBAC permission model so access is managed with the same roles, PIM and reviews as everything else.", "Medium",
            f => Header(f, $"Switch Key Vault '{f.ResourceName}' to RBAC authorization (assign Key Vault roles first)") +
                 $"az keyvault update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --enable-rbac-authorization true"),
        ["Key Vault public access"] = new("Disable public network access and reach the vault through a private endpoint, or restrict the firewall to trusted services and known networks.", "Medium",
            f => Header(f, $"Disable public access on Key Vault '{f.ResourceName}'") +
                 $"az keyvault update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --public-network-access Disabled"),
        ["Outdated TLS on SQL"] = new("Set the minimal TLS version on the logical server to 1.2.", "Low",
            f => Header(f, $"Require TLS 1.2 on SQL server '{f.ResourceName}'") +
                 $"az sql server update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --minimal-tls-version 1.2"),
        ["SQL not Entra-only"] = new("Set a Microsoft Entra administrator and enable Entra-only authentication so SQL logins (and their passwords) are no longer an attack path.", "Medium",
            f => Header(f, $"Enable Entra-only authentication on SQL server '{f.ResourceName}'") +
                 $"az sql server ad-admin create --resource-group \"{Rg(f)}\" --server-name \"{f.ResourceName}\" --display-name \"<admin-group>\" --object-id \"<group-object-id>\"\naz sql server ad-only-auth enable --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\""),
        ["SQL public access"] = new("Disable public network access on the logical server and connect through a private endpoint.", "Medium",
            f => Header(f, $"Disable public access on SQL server '{f.ResourceName}'") +
                 $"az sql server update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --enable-public-network false"),
        ["Activity log not exported"] = new("Add a subscription diagnostic setting that sends the Activity Log (Administrative, Security, Policy, Alert) to a Log Analytics workspace so changes are retained beyond 90 days and can be alerted on.", "Low",
            f => Header(f, "Export the Activity Log to Log Analytics") +
                 $"az monitor diagnostic-settings subscription create --name activity-to-law --location global --workspace \"<log-analytics-workspace-id>\" --logs '[{{\"category\":\"Administrative\",\"enabled\":true}},{{\"category\":\"Security\",\"enabled\":true}},{{\"category\":\"Policy\",\"enabled\":true}},{{\"category\":\"Alert\",\"enabled\":true}},{{\"category\":\"ServiceHealth\",\"enabled\":true}}]'"),
        ["No Log Analytics workspace"] = new("Create a central Log Analytics workspace and point resource diagnostic settings, the Activity Log and Defender for Cloud at it.", "Low",
            f => Header(f, "Create a Log Analytics workspace") +
                 "az monitor log-analytics workspace create --resource-group \"rg-monitoring\" --workspace-name \"law-central\" --location \"<region>\""),

        // ── Storage ──────────────────────────────────────────────────────────
        ["Blob public access allowed"] = new("Disallow blob public access at the account level. If a container genuinely needs anonymous reads, serve it through a CDN or Front Door instead.", "Low",
            f => Header(f, $"Disallow public blob access on '{f.ResourceName}'") +
                 $"az storage account update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --allow-blob-public-access false"),
        ["HTTP allowed on storage"] = new("Require secure transfer so every request must use HTTPS/SMB 3 with encryption.", "Low",
            f => Header(f, $"Require HTTPS on '{f.ResourceName}'") +
                 $"az storage account update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --https-only true"),
        ["Outdated TLS on storage"] = new("Set the minimum TLS version to 1.2.", "Low",
            f => Header(f, $"Require TLS 1.2 on '{f.ResourceName}'") +
                 $"az storage account update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --min-tls-version TLS1_2"),
        ["Shared key access enabled"] = new("Move clients to Microsoft Entra authorization (managed identities + RBAC data roles) and then disable shared key access so a leaked account key is worthless.", "Medium",
            f => Header(f, $"Disable shared key access on '{f.ResourceName}' (only after all clients use Entra auth)") +
                 $"az storage account update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --allow-shared-key-access false"),
        ["Storage public network access"] = new("Set the network default action to Deny (allowing only required VNets, IPs and trusted services) or disable public network access and use a private endpoint.", "Medium",
            f => Header(f, $"Deny public network access on '{f.ResourceName}' by default") +
                 $"az storage account update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --default-action Deny --bypass AzureServices"),
        ["No private endpoint"] = new("Add a private endpoint for the blob (and other used) sub-resources so traffic from the VNet never crosses the public Internet.", "Medium"),
        ["Blob soft delete off"] = new("Enable blob soft delete (7–30 days) so accidental or malicious deletions and overwrites can be undone.", "Low",
            f => Header(f, $"Enable blob soft delete on '{f.ResourceName}'") +
                 $"az storage account blob-service-properties update --resource-group \"{Rg(f)}\" --account-name \"{f.ResourceName}\" --enable-delete-retention true --delete-retention-days 14"),
        ["Container soft delete off"] = new("Enable container soft delete so a deleted container can be restored.", "Low",
            f => Header(f, $"Enable container soft delete on '{f.ResourceName}'") +
                 $"az storage account blob-service-properties update --resource-group \"{Rg(f)}\" --account-name \"{f.ResourceName}\" --enable-container-delete-retention true --container-delete-retention-days 14"),
        ["Versioning off"] = new("Enable blob versioning (with a lifecycle rule to expire old versions) for accounts holding data that must survive overwrites or ransomware.", "Low",
            f => Header(f, $"Enable blob versioning on '{f.ResourceName}'") +
                 $"az storage account blob-service-properties update --resource-group \"{Rg(f)}\" --account-name \"{f.ResourceName}\" --enable-versioning true"),
        ["Locally redundant storage"] = new("LRS keeps three copies in one datacentre. For production data use ZRS (zone failure) or GRS/GZRS (regional failure) unless the data is reproducible.", "Low",
            f => Header(f, $"Change '{f.ResourceName}' to zone-redundant storage") +
                 $"az storage account update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --sku Standard_ZRS"),
        ["No lifecycle policy"] = new("Add a lifecycle management policy that moves cold blobs to Cool/Archive and deletes old versions, snapshots and logs — usually the biggest storage saving available.", "Low"),
        ["Storage v1 account"] = new("Upgrade the general-purpose v1 account to v2 to get access tiers, lifecycle management, soft delete and the current pricing model.", "Low",
            f => Header(f, $"Upgrade '{f.ResourceName}' to StorageV2") +
                 $"az storage account update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --set kind=StorageV2 --access-tier Hot"),
        ["Infrastructure encryption off"] = new("Infrastructure (double) encryption can only be set at creation. For regulated data, recreate the account with it enabled and migrate the content.", "High"),
        ["Cross-tenant replication allowed"] = new("Disallow cross-tenant object replication unless replication to another tenant is an explicit requirement.", "Low",
            f => Header(f, $"Disallow cross-tenant replication on '{f.ResourceName}'") +
                 $"az storage account update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --allow-cross-tenant-replication false"),
        ["Shared key default in portal"] = new("Default the portal and tools to Microsoft Entra authorization so engineers stop using account keys by habit.", "Low",
            f => Header(f, $"Default '{f.ResourceName}' to Entra authorization") +
                 $"az storage account update --resource-group \"{Rg(f)}\" --name \"{f.ResourceName}\" --default-to-oauth-authentication true"),

        // ── Microsoft Entra ID ───────────────────────────────────────────────
        ["No MFA for all users"] = new("Create a Conditional Access policy that requires multifactor authentication (or a phishing-resistant authentication strength) for all users on all cloud apps, with a break-glass exclusion. Roll out in report-only mode first.", "Medium"),
        ["No MFA for admins"] = new("Create a Conditional Access policy requiring phishing-resistant MFA for all directory roles (Global Administrator, Privileged Role Administrator, Security Administrator, etc.).", "Low"),
        ["Legacy authentication allowed"] = new("Create a Conditional Access policy that blocks legacy authentication clients (Exchange ActiveSync and 'other clients') for all users — legacy protocols cannot do MFA and are the main password-spray target.", "Low"),
        ["No MFA enforcement"] = new("Neither security defaults nor a Conditional Access MFA policy is in force. Enable security defaults (free tenants) or build a Conditional Access baseline with MFA for everyone.", "Medium"),
        ["Too few Global Administrators"] = new("Have at least two Global Administrators (one can be a cloud-only emergency access account) so the tenant is never locked out when one person is unavailable.", "Low"),
        ["Too many Global Administrators"] = new("Reduce Global Administrators to fewer than five. Move day-to-day administrators to least-privileged roles and make the rest eligible through PIM rather than permanent.", "Medium"),
        ["Guest in privileged role"] = new("Remove guest (external) accounts from privileged directory roles; external identities are not covered by the organisation's own identity controls.", "Low"),
        ["Guest invites unrestricted"] = new("Restrict who can invite guests to administrators and users in the Guest Inviter role, so external access goes through a known process.", "Low"),
        ["Guest permissions not restricted"] = new("Set guest user access to 'restricted' so guests can only see their own objects, not enumerate the whole directory.", "Low"),
        ["Users can register applications"] = new("Prevent ordinary users from registering applications; route app registrations through an owner-approved process.", "Low"),
        ["Users can create tenants"] = new("Prevent ordinary users from creating new Entra tenants, which escape all of the organisation's controls.", "Low"),
        ["User consent allowed"] = new("Restrict user consent to verified publishers and low-impact permissions (or disable it) and set up the admin consent workflow, so a malicious OAuth app cannot be granted access to mail and files by a single user.", "Low"),
        ["No risk-based policy"] = new("Add Conditional Access policies that require MFA for medium/high sign-in risk and a password change for high user risk (requires Entra ID P2).", "Medium"),
        ["No device compliance policy"] = new("Require a compliant or hybrid-joined device for access to sensitive apps so a stolen password alone is not enough from an unmanaged device.", "High"),
        ["Weak authentication methods"] = new("Disable SMS and voice-call authentication (or restrict them to a migration group) and promote Microsoft Authenticator, FIDO2 or Windows Hello for Business.", "Medium"),
        ["Report-only policy"] = new("The policy is in report-only mode and is not enforcing anything. Review the sign-in impact and switch it on.", "Low"),

        // ── Identity and Access Management ───────────────────────────────────
        ["Too many Owners at subscription scope"] = new("Keep subscription-level Owner to at most three principals (ideally a PIM-eligible group). Give everyone else Contributor or a built-in role scoped to a resource group.", "Medium"),
        ["Privileged role assigned to user"] = new("Assign privileged roles to Entra groups (PIM-eligible where possible) rather than to individual users, so access is reviewable and offboarding is automatic.", "Medium"),
        ["Custom role with wildcard"] = new("Replace '*' style actions with the explicit operations the role needs; wildcard custom roles are Owner in disguise and are hard to audit.", "Medium"),
        ["Service principal with Owner"] = new("Service principals should not be Owner. Scope the workload identity to Contributor (or a narrower built-in role) on the resource groups it actually deploys to.", "Medium"),
        ["Orphaned role assignment"] = new("The principal could not be found in this directory: it was deleted, or it belongs to another tenant (CSP, Lighthouse or a partner identity). If it is genuinely gone, remove the assignment to keep the access list truthful and to avoid identity re-use attacks; if it is a known cross-tenant identity, document it.", "Low",
            f => Header(f, "Remove the orphaned role assignment") +
                 $"az role assignment delete --ids \"{f.ResourceId}\""),
        ["Guest with role assignment"] = new("Review whether an external identity should have this access at all; if so, scope it tightly and set an access review and expiry.", "Low"),
        ["User Access Administrator on user"] = new("User Access Administrator lets a user grant anyone any role. Reserve it for a PIM-eligible group and remove it from standing user assignments.", "Low"),
        ["Expired app credentials"] = new("Remove expired client secrets and certificates from app registrations; they are noise that hides the ones that matter and signal unmanaged automation.", "Low"),
        ["Long-lived app credentials"] = new("Rotate client secrets to a maximum of 12 months (or replace them with certificates, federated credentials or managed identities).", "Medium"),
        ["No user-assigned identities"] = new("Workloads that run outside Azure compute (or share an identity across instances) should use user-assigned managed identities instead of app registration secrets.", "Low"),
    };

    public static Entry For(string category) =>
        Entries.TryGetValue(category, out var e) ? e : new Entry("Review this finding in the Azure portal and adjust the configuration to match Microsoft's guidance.", "Medium");
}

/// <summary>Collects findings from the assessors and fills in fix, effort and script from the catalog.</summary>
internal sealed class FindingSink
{
    public List<AuditFinding> Items { get; } = new();

    public AuditFinding Add(AuditArea area, string severity, string category, string message, ResourceBase r) =>
        Add(area, severity, category, message, r.Name, r.Id, r.ResourceGroup, r.SubscriptionId);

    public AuditFinding Add(AuditArea area, string severity, string category, string message, string name, string id = "", string rg = "", string subId = "")
    {
        var entry = FindingCatalog.For(category);
        var f = new AuditFinding
        {
            Area = area, Severity = severity, Category = category, Message = message,
            ResourceName = name, ResourceId = string.IsNullOrEmpty(id) ? name : id, ResourceGroup = rg, SubscriptionId = subId,
            Fix = entry.Fix, Effort = entry.Effort,
        };
        f.Script = entry.Script?.Invoke(f);
        Items.Add(f);
        return f;
    }
}
