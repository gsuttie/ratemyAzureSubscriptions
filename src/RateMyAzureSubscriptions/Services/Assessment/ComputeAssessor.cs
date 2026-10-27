using RateMyAzureSubscriptions.Models;

namespace RateMyAzureSubscriptions.Services.Assessment;

/// <summary>
/// Compute (100): availability &amp; resilience 25 · backup 20 · configuration &amp; security 25 ·
/// performance &amp; sizing 15 · cost optimisation 15.
/// Caps: unmanaged disks → max B · no VM backed up at all → max C.
/// </summary>
internal static class ComputeAssessor
{
    public const string AvailabilityCategory = "Availability & resilience";
    public const string BackupCategory = "Backup & recovery";
    public const string ConfigCategory = "Configuration & security";
    public const string PerformanceCategory = "Performance & sizing";
    public const string CostCategory = "Cost optimisation";

    public static AreaRating Assess(AuditScanResult scan, FindingSink findings)
    {
        var area = AuditArea.Compute;
        var vms = scan.VirtualMachines;
        var apps = scan.WebApps;
        var plans = scan.AppServicePlans;
        var activeVms = vms.Where(v => !v.IsDeallocated).ToList();

        if (vms.Count == 0 && apps.Count == 0 && plans.Count == 0)
            return RatingBuilder.NotAssessed(area, "No virtual machines, App Services or App Service plans in the scanned subscriptions.");

        var b = new RatingBuilder(area);

        // ── 1. Availability & resilience (25) ────────────────────────────────
        var avail = b.Category(AvailabilityCategory, 25);
        var zonal = vms.Count(v => v.IsZonalOrInSet);
        b.Check(avail, 15, zonal, vms.Count,
            vms.Count == 0 ? "No VMs to assess." : $"{zonal} of {vms.Count} VM(s) use an availability zone or availability set.",
            $"Place the {vms.Count - zonal} VM(s) without zone or availability-set protection into availability zones.");
        foreach (var v in vms.Where(v => !v.IsZonalOrInSet))
            findings.Add(area, "Medium", "No availability zone or set", $"VM '{v.Name}' ({v.Size}) runs as a single instance with no availability zone or availability set.", v);

        var prodPlans = plans.Where(p => !p.IsEmpty && !p.IsConsumption && !p.IsFreeOrShared).ToList();
        var resilientPlans = prodPlans.Count(p => !p.IsSingleInstanceProductionRisk);
        b.Check(avail, 10, resilientPlans, prodPlans.Count,
            prodPlans.Count == 0 ? "No dedicated App Service plans to assess." : $"{resilientPlans} of {prodPlans.Count} App Service plan(s) run more than one instance or are zone redundant.",
            $"Scale the {prodPlans.Count - resilientPlans} single-instance App Service plan(s) to two or more instances.");
        foreach (var p in prodPlans.Where(p => p.IsSingleInstanceProductionRisk))
            findings.Add(area, "Medium", "Single-instance plan", $"App Service plan '{p.Name}' ({p.SkuName}) runs a single instance hosting {p.NumberOfSites} app(s).", p);

        // ── 2. Backup & recovery (20) ────────────────────────────────────────
        var backup = b.Category(BackupCategory, 20);
        var backupKnown = vms.Where(v => v.IsBackedUp is not null).ToList();
        if (vms.Count == 0)
        {
            backup.Earned = 20;
            backup.Details.Add("No VMs to assess.");
        }
        else if (backupKnown.Count == 0)
        {
            backup.Earned = 10;
            backup.Details.Add("Backup state could not be determined — half points awarded.");
        }
        else
        {
            var backedUp = backupKnown.Count(v => v.IsBackedUp == true);
            b.Check(backup, 20, backedUp, backupKnown.Count,
                $"{backedUp} of {backupKnown.Count} VM(s) are protected by Azure Backup.",
                $"Enable Azure Backup on the {backupKnown.Count - backedUp} unprotected VM(s).", "nobackup");
            if (backedUp == 0)
                b.Cap("nobackup", "C", "No virtual machine is protected by Azure Backup.");
            foreach (var v in backupKnown.Where(v => v.IsBackedUp == false))
                findings.Add(area, v.IsDeallocated ? "Low" : "High", "VM not backed up", $"VM '{v.Name}' is not protected by Azure Backup.", v);
        }

        // ── 3. Configuration & security (25) ─────────────────────────────────
        var config = b.Category(ConfigCategory, 25);
        var managed = vms.Count(v => v.UsesManagedDisks);
        b.Check(config, 7, managed, vms.Count,
            vms.Count == 0 ? "No VMs to assess." : $"{managed} of {vms.Count} VM(s) use managed disks.",
            $"Convert the {vms.Count - managed} VM(s) on unmanaged disks to managed disks.", "unmanaged");
        if (managed < vms.Count)
            b.Cap("unmanaged", "B", "Some VMs still use unmanaged disks (storage-account VHDs).");
        foreach (var v in vms.Where(v => !v.UsesManagedDisks))
            findings.Add(area, "High", "Unmanaged disks", $"VM '{v.Name}' uses unmanaged disks in a storage account.", v);

        var bootDiag = vms.Count(v => v.BootDiagnosticsEnabled);
        b.Check(config, 5, bootDiag, vms.Count,
            vms.Count == 0 ? "No VMs to assess." : $"{bootDiag} of {vms.Count} VM(s) have boot diagnostics enabled.",
            $"Enable boot diagnostics on the {vms.Count - bootDiag} VM(s) without it.");
        foreach (var v in vms.Where(v => !v.BootDiagnosticsEnabled))
            findings.Add(area, "Low", "Boot diagnostics off", $"VM '{v.Name}' has boot diagnostics disabled.", v);

        var httpsOnly = apps.Count(a => a.HttpsOnly);
        b.Check(config, 5, httpsOnly, apps.Count,
            apps.Count == 0 ? "No App Services to assess." : $"{httpsOnly} of {apps.Count} App Service(s) enforce HTTPS only.",
            $"Enable HTTPS-only on the {apps.Count - httpsOnly} App Service(s) still accepting HTTP.");
        foreach (var a in apps.Where(a => !a.HttpsOnly))
            findings.Add(area, "Medium", "HTTPS only off", $"{a.TypeLabel} '{a.Name}' accepts plain HTTP requests.", a);

        var tlsOk = apps.Count(a => a.TlsOk && a.FtpsOk);
        b.Check(config, 4, tlsOk, apps.Count,
            apps.Count == 0 ? "No App Services to assess." : $"{tlsOk} of {apps.Count} App Service(s) require TLS 1.2 and have FTP disabled.",
            $"Set minimum TLS 1.2 and disable FTP on the {apps.Count - tlsOk} App Service(s) with weaker transport settings.");
        foreach (var a in apps.Where(a => !a.TlsOk))
            findings.Add(area, "Medium", "Outdated TLS on web app", $"{a.TypeLabel} '{a.Name}' allows TLS {a.MinTlsVersion}.", a);
        foreach (var a in apps.Where(a => !a.FtpsOk))
            findings.Add(area, "Low", "FTP enabled on web app", $"{a.TypeLabel} '{a.Name}' allows plain FTP deployments ({a.FtpsState}).", a);

        var identities = apps.Count(a => a.HasManagedIdentity);
        b.Check(config, 4, identities, apps.Count,
            apps.Count == 0 ? "No App Services to assess." : $"{identities} of {apps.Count} App Service(s) have a managed identity.",
            $"Assign managed identities to the {apps.Count - identities} App Service(s) without one.");
        foreach (var a in apps.Where(a => !a.HasManagedIdentity))
            findings.Add(area, "Low", "No managed identity", $"{a.TypeLabel} '{a.Name}' has no managed identity; it must be using secrets or keys to reach other services.", a);

        // ── 4. Performance & sizing (15) ─────────────────────────────────────
        var perf = b.Category(PerformanceCategory, 15);
        var currentGen = vms.Count(v => !v.IsPreviousGenerationSize);
        b.Check(perf, 8, currentGen, vms.Count,
            vms.Count == 0 ? "No VMs to assess." : $"{currentGen} of {vms.Count} VM(s) use a current-generation size.",
            $"Resize the {vms.Count - currentGen} VM(s) on previous-generation sizes.");
        foreach (var v in vms.Where(v => v.IsPreviousGenerationSize))
            findings.Add(area, "Low", "Previous-generation VM size", $"VM '{v.Name}' uses {v.Size}, a previous-generation size with cheaper and faster successors.", v);

        var usedPlans = plans.Where(p => !p.IsEmpty).ToList();
        var paidPlans = usedPlans.Count(p => !p.IsFreeOrShared);
        b.Check(perf, 4, paidPlans, usedPlans.Count,
            usedPlans.Count == 0 ? "No App Service plans to assess." : $"{paidPlans} of {usedPlans.Count} App Service plan(s) are on a tier with an SLA.",
            $"Move the {usedPlans.Count - paidPlans} Free/Shared plan(s) to Basic or above.");
        foreach (var p in usedPlans.Where(p => p.IsFreeOrShared))
            findings.Add(area, "Low", "Free or Shared plan", $"App Service plan '{p.Name}' is on the {p.SkuTier} tier (no SLA) and hosts {p.NumberOfSites} app(s).", p);

        var alwaysOnKnown = apps.Where(a => a.AlwaysOn is not null && !a.IsFunctionApp).ToList();
        var alwaysOn = alwaysOnKnown.Count(a => a.AlwaysOn == true);
        b.Check(perf, 3, alwaysOn, alwaysOnKnown.Count,
            alwaysOnKnown.Count == 0 ? "Always On state not available." : $"{alwaysOn} of {alwaysOnKnown.Count} web app(s) have Always On enabled.",
            $"Enable Always On for the {alwaysOnKnown.Count - alwaysOn} web app(s) that unload when idle.");
        foreach (var a in alwaysOnKnown.Where(a => a.AlwaysOn == false))
            findings.Add(area, "Low", "Always On disabled", $"App Service '{a.Name}' has Always On disabled and will cold-start after idle periods.", a);

        // ── 5. Cost optimisation (15) ────────────────────────────────────────
        var cost = b.Category(CostCategory, 15);
        var stopped = vms.Where(v => v.IsStoppedNotDeallocated).ToList();
        b.Check(cost, 5, vms.Count - stopped.Count, vms.Count,
            vms.Count == 0 ? "No VMs to assess." : stopped.Count == 0 ? "No VM is stopped without being deallocated." : $"{stopped.Count} VM(s) are stopped but still allocated and billed.",
            $"Deallocate the {stopped.Count} stopped VM(s) that are still billed.");
        foreach (var v in stopped)
            findings.Add(area, "Medium", "Stopped VM still billed", $"VM '{v.Name}' is stopped inside the OS but not deallocated, so its compute is still billed.", v);

        var unattached = scan.Disks.Where(d => d.IsUnattached).ToList();
        b.Check(cost, 5, scan.Disks.Count - unattached.Count, scan.Disks.Count,
            scan.Disks.Count == 0 ? "No managed disks to assess." : unattached.Count == 0 ? "Every managed disk is attached to a VM." : $"{unattached.Count} of {scan.Disks.Count} managed disk(s) are unattached ({unattached.Sum(d => d.SizeGb)} GB).",
            $"Delete or snapshot the {unattached.Count} unattached disk(s).");
        foreach (var d in unattached)
            findings.Add(area, "Low", "Unattached disk", $"Disk '{d.Name}' ({d.SizeGb} GB, {d.Sku}) is not attached to any VM.", d);

        var empty = plans.Where(p => p.IsEmpty && !p.IsFreeOrShared).ToList();
        b.Check(cost, 3, plans.Count - empty.Count, plans.Count,
            plans.Count == 0 ? "No App Service plans to assess." : empty.Count == 0 ? "No empty App Service plans." : $"{empty.Count} App Service plan(s) host no apps.",
            $"Delete the {empty.Count} empty App Service plan(s).");
        foreach (var p in empty)
            findings.Add(area, "Low", "Empty App Service plan", $"App Service plan '{p.Name}' ({p.SkuName}) hosts no apps but is billed.", p);

        var windows = activeVms.Where(v => v.IsWindows).ToList();
        var ahb = windows.Count(v => v.HasHybridBenefit);
        b.Check(cost, 2, ahb, windows.Count,
            windows.Count == 0 ? "No Windows VMs to assess." : $"{ahb} of {windows.Count} Windows VM(s) use Azure Hybrid Benefit.",
            $"Apply Azure Hybrid Benefit to the {windows.Count - ahb} Windows VM(s) without it (if licences are available).");
        foreach (var v in windows.Where(v => !v.HasHybridBenefit))
            findings.Add(area, "Low", "No Azure Hybrid Benefit", $"Windows VM '{v.Name}' pays for its Windows licence in the hourly rate.", v);

        var parts = new List<string>();
        if (vms.Count > 0) parts.Add($"{vms.Count} VM{(vms.Count == 1 ? "" : "s")}");
        if (apps.Count > 0) parts.Add($"{apps.Count} App Service{(apps.Count == 1 ? "" : "s")}");
        if (plans.Count > 0) parts.Add($"{plans.Count} plan{(plans.Count == 1 ? "" : "s")}");
        if (scan.Disks.Count > 0) parts.Add($"{scan.Disks.Count} disk{(scan.Disks.Count == 1 ? "" : "s")}");
        return b.Build(vms.Count + apps.Count + plans.Count, string.Join(", ", parts));
    }
}
