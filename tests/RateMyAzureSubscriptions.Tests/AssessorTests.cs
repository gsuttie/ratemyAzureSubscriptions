using Microsoft.Extensions.Configuration;
using RateMyAzureSubscriptions.Models;
using RateMyAzureSubscriptions.Services;
using RateMyAzureSubscriptions.Services.Assessment;
using Xunit;

namespace RateMyAzureSubscriptions.Tests;

/// <summary>The rating engine and the six area assessors, driven by hand-built estates and the sample data.</summary>
public class AssessorTests
{
    [Theory]
    [InlineData(100, "A")]
    [InlineData(90, "A")]
    [InlineData(89, "B")]
    [InlineData(75, "B")]
    [InlineData(60, "C")]
    [InlineData(45, "D")]
    [InlineData(30, "E")]
    [InlineData(0, "F")]
    public void GradeBands(int score, string grade) => Assert.Equal(grade, AuditRatingService.GradeForScore(score));

    [Fact]
    public void Prorate_FullMarksWhenNothingToAssess_AndNeverFullForPartial()
    {
        Assert.Equal(10, RatingBuilder.Prorate(10, 0, 0));
        Assert.Equal(10, RatingBuilder.Prorate(10, 5, 5));
        Assert.Equal(0, RatingBuilder.Prorate(10, 0, 5));
        Assert.InRange(RatingBuilder.Prorate(10, 99, 100), 1, 9);
        Assert.InRange(RatingBuilder.Prorate(10, 1, 100), 1, 9);
    }

    [Fact]
    public void RatingBuilder_AppliesCapsAndLiftsThemPerImprovement()
    {
        var b = new RatingBuilder(AuditArea.Compute);
        var c = b.Category("x", 100);
        c.Earned = 95;
        b.Cap("k", "C", "capped");
        b.Improve("lift", 5, "k");
        b.Improve("other", 1);
        var r = b.Build(1, "one");
        Assert.Equal(95, r.Score);
        Assert.Equal("C", r.Grade);
        Assert.Equal("capped", r.CapReason);
        Assert.Equal("A", r.Improvements.First(i => i.Action == "lift").ResultingGrade);
        Assert.Equal("C", r.Improvements.First(i => i.Action == "other").ResultingGrade);
    }

    [Fact]
    public void SampleEstate_ProducesAllSixAreasAndSpreadsGrades()
    {
        var scan = DemoDataService.Scan([DemoDataService.SubProd, DemoDataService.SubDev]);
        Assert.Equal(6, scan.Ratings.Count);
        Assert.All(scan.Ratings, r => Assert.False(r.NotAssessed));
        Assert.All(scan.Ratings, r => Assert.Equal(100, r.Categories.Sum(c => c.Possible)));
        Assert.True(scan.Ratings.Select(r => r.Grade).Distinct().Count() >= 3, "sample data should spread across grade bands");
        Assert.NotEmpty(scan.Findings);
        Assert.Contains(scan.Findings, f => f.Severity == "High");
        Assert.All(scan.Findings, f => Assert.False(string.IsNullOrWhiteSpace(f.Fix)));
        Assert.All(scan.Findings, f => Assert.Contains(f.Effort, new[] { "Low", "Medium", "High" }));
        Assert.Contains(scan.Findings, f => f.Script is not null && f.Script.Contains("az "));
    }

    [Fact]
    public void SampleEstate_ProductionOnlyScoresBetterThanDevOnly()
    {
        var prod = DemoDataService.Scan([DemoDataService.SubProd]);
        var dev = DemoDataService.Scan([DemoDataService.SubDev]);
        foreach (var area in new[] { AuditArea.Compute, AuditArea.Networking, AuditArea.Security, AuditArea.Storage, AuditArea.Iam })
            Assert.True(prod.Rating(area)!.Score > dev.Rating(area)!.Score, $"{area}: prod {prod.Rating(area)!.Score} should beat dev {dev.Rating(area)!.Score}");
        Assert.Equal(prod.Rating(AuditArea.EntraId)!.Score, dev.Rating(AuditArea.EntraId)!.Score); // tenant-wide
    }

    [Fact]
    public void Networking_OpenManagementPortCapsAtD()
    {
        var scan = DemoDataService.Scan([DemoDataService.SubDev]);
        var net = scan.Rating(AuditArea.Networking)!;
        Assert.True(string.CompareOrdinal(net.Grade, "D") >= 0, $"grade was {net.Grade}");
        Assert.Contains(scan.Findings, f => f.Category == "Management port open to Internet" && f.ResourceName == "nsg-dev");

        // An otherwise well-run estate with one Internet-facing RDP rule is capped at D, whatever its score.
        var prod = DemoDataService.Scan([DemoDataService.SubProd]);
        Assert.True(prod.Rating(AuditArea.Networking)!.Score >= 75, "production networking should score well");
        prod.NetworkSecurityGroups.First(n => n.Name == "nsg-app").Rules.Add(new NsgRuleInfo { Name = "oops-rdp", Priority = 150, Direction = "Inbound", Access = "Allow", Protocol = "Tcp", Sources = ["*"], DestinationPorts = ["3389"] });
        AuditRatingService.AssessAll(prod);
        var capped = prod.Rating(AuditArea.Networking)!;
        Assert.Equal("D", capped.Grade);
        Assert.Contains("Internet", capped.CapReason);
    }

    [Fact]
    public void Storage_PublicBlobAccessCapsAtC()
    {
        var scan = DemoDataService.Scan([DemoDataService.SubDev]);
        var st = scan.Rating(AuditArea.Storage)!;
        Assert.True(string.CompareOrdinal(st.Grade, "C") >= 0);
        Assert.Contains(scan.Findings, f => f.Category == "Blob public access allowed" && f.ResourceName == "stcontosodev");
    }

    [Fact]
    public void Entra_NoMfaForAllUsersIsFlagged_AndSecurityDefaultsCount()
    {
        var scan = DemoDataService.Scan([DemoDataService.SubProd]);
        Assert.Contains(scan.Findings, f => f.Category == "No MFA for all users");
        Assert.DoesNotContain(scan.Findings, f => f.Category == "Legacy authentication allowed");
        Assert.Contains(scan.Findings, f => f.Category == "Too many Global Administrators");
        Assert.Contains(scan.Findings, f => f.Category == "Report-only policy");

        var withDefaults = DemoDataService.Estate();
        withDefaults.Entra.SecurityDefaultsEnabled = true;
        withDefaults.Entra.ConditionalAccessPolicies.Clear();
        AuditRatingService.AssessAll(withDefaults);
        var mfa = withDefaults.Rating(AuditArea.EntraId)!.Categories.First(c => c.Name == EntraAssessor.MfaCategory);
        Assert.Equal(35, mfa.Earned);
    }

    [Fact]
    public void Entra_UnreadableGraphIsNotAssessed()
    {
        var estate = DemoDataService.Estate();
        estate.Entra = new EntraTenantInfo { ReadError = "no graph" };
        AuditRatingService.AssessAll(estate);
        var r = estate.Rating(AuditArea.EntraId)!;
        Assert.True(r.NotAssessed);
        Assert.Equal("–", r.Grade);
        Assert.DoesNotContain(estate.Findings, f => f.Area == AuditArea.EntraId);
        Assert.True(estate.OverallScore > 0);
    }

    [Fact]
    public void Iam_TooManyOwnersCapsAtC_AndWildcardRoleFlagged()
    {
        var scan = DemoDataService.Scan([DemoDataService.SubDev]);
        var iam = scan.Rating(AuditArea.Iam)!;
        Assert.True(string.CompareOrdinal(iam.Grade, "C") >= 0);
        Assert.Contains(scan.Findings, f => f.Category == "Custom role with wildcard" && f.ResourceName == "Dev Super User");
        Assert.Contains(scan.Findings, f => f.Category == "Orphaned role assignment" && f.Script!.Contains("az role assignment delete"));
        Assert.Contains(scan.Findings, f => f.Category == "Guest with role assignment");
    }

    [Fact]
    public void Compute_EmptyEstateIsNotAssessed()
    {
        var scan = new AuditScanResult();
        AuditRatingService.AssessAll(scan);
        Assert.All(scan.Ratings, r => Assert.True(r.NotAssessed));
        Assert.Empty(scan.Findings);
        Assert.Equal("–", AuditRatingService.OverallGrade(scan));
    }

    [Fact]
    public void OverallGrade_NeverMoreThanOneBandAboveWeakest()
    {
        var scan = DemoDataService.Scan([DemoDataService.SubProd, DemoDataService.SubDev]);
        var worst = AuditRatingService.Worst(scan.Ratings)!;
        var overall = AuditRatingService.OverallGrade(scan);
        Assert.True(overall[0] >= worst.Grade[0] - 1, $"overall {overall} vs worst {worst.Grade}");
    }

    [Fact]
    public void Findings_OrderedByPriorityAndCarryCatalogGuidance()
    {
        var scan = DemoDataService.Scan([DemoDataService.SubProd, DemoDataService.SubDev]);
        var priorities = scan.Findings.Select(f => f.Priority).ToList();
        Assert.Equal(priorities.OrderBy(p => p), priorities);
        foreach (var f in scan.Findings)
            Assert.True(FindingCatalog.Entries.ContainsKey(f.Category), $"no catalog entry for '{f.Category}'");
    }

    [Fact]
    public void NsgRule_PortRangesAndInternetSources()
    {
        var rule = new NsgRuleInfo { Direction = "Inbound", Access = "Allow", Sources = ["Internet"], DestinationPorts = ["3000-4000"] };
        Assert.True(rule.IsInboundAllow && rule.FromInternet);
        Assert.True(NsgRuleInfo.PortRangeContains("3000-4000", 3389));
        Assert.True(rule.OpensManagementPort);
        rule.DestinationPorts = ["443"];
        Assert.False(rule.OpensManagementPort);
        rule.Sources = ["10.0.0.0/8"];
        Assert.False(rule.FromInternet);
    }

    [Theory]
    [InlineData("Standard_D2_v2", true)]
    [InlineData("Standard_A4", true)]
    [InlineData("Basic_A1", true)]
    [InlineData("Standard_DS3", true)]
    [InlineData("Standard_D4s_v5", false)]
    [InlineData("Standard_B2ms", false)]
    [InlineData("Standard_E8s_v5", false)]
    public void VmSize_PreviousGenerationDetection(string size, bool previous) =>
        Assert.Equal(previous, new VirtualMachineInfo { Size = size }.IsPreviousGenerationSize);
}

/// <summary>Auditing areas one at a time and merging them into the same result.</summary>
public class AreaMergeTests
{
    [Fact]
    public void PartialScan_RatesOnlySelectedAreas_AndMergesLater()
    {
        var subs = new[] { DemoDataService.SubProd, DemoDataService.SubDev };
        var first = DemoDataService.Scan(subs, [AuditArea.Storage, AuditArea.Compute]);
        Assert.False(first.Rating(AuditArea.Storage)!.NotAssessed);
        Assert.False(first.Rating(AuditArea.Compute)!.NotAssessed);
        Assert.True(first.Rating(AuditArea.Networking)!.NotAssessed);
        Assert.Contains("Not audited yet", first.Rating(AuditArea.Networking)!.NotAssessedReason);
        Assert.Equal(4, first.PendingAreas.Count());
        Assert.DoesNotContain(first.Findings, f => f.Area == AuditArea.Networking);
        var storageScore = first.Rating(AuditArea.Storage)!.Score;

        var second = DemoDataService.Scan(subs, [AuditArea.Networking, AuditArea.EntraId]);
        AuditFlowService.Merge(first, second, new HashSet<AuditArea> { AuditArea.Networking, AuditArea.EntraId });
        AuditDiscoveryService.Finalize(first);
        Assert.False(first.Rating(AuditArea.Networking)!.NotAssessed);
        Assert.False(first.Rating(AuditArea.EntraId)!.NotAssessed);
        Assert.Equal(storageScore, first.Rating(AuditArea.Storage)!.Score);
        Assert.Equal(2, first.PendingAreas.Count());
        Assert.Contains(first.Findings, f => f.Area == AuditArea.Networking);

        var full = DemoDataService.Scan(subs);
        var third = DemoDataService.Scan(subs, [AuditArea.Security, AuditArea.Iam]);
        AuditFlowService.Merge(first, third, new HashSet<AuditArea> { AuditArea.Security, AuditArea.Iam });
        AuditDiscoveryService.Finalize(first);
        Assert.Empty(first.PendingAreas);
        foreach (var area in AuditAreaExtensions.All)
            Assert.Equal(full.Rating(area)!.Score, first.Rating(area)!.Score);
        Assert.Equal(full.Findings.Count, first.Findings.Count);
    }
}

/// <summary>Restore tests (name or resource group containing "restore") never take part in a review.</summary>
public class ExclusionTests
{
    [Theory]
    [InlineData("vm-crm-restore-01", "rg-prod", true)]
    [InlineData("vm-app-01", "rg-Restore-Test", true)]
    [InlineData("RESTOREDB", "rg-data", true)]
    [InlineData("vm-app-01", "rg-prod", false)]
    public void NameOrResourceGroupContainingRestoreIsExcluded(string name, string rg, bool excluded) =>
        Assert.Equal(excluded, ExclusionRules.Default.IsExcluded(name, rg));

    [Fact]
    public void ArmIdsAreMatchedOnResourceGroupAndResourceSegments()
    {
        Assert.True(ExclusionRules.Default.IsExcludedId("/subscriptions/s/resourceGroups/rg-restore-test"));
        Assert.True(ExclusionRules.Default.IsExcludedId("/subscriptions/s/resourceGroups/rg-restore-test/providers/Microsoft.Compute/virtualMachines/vm1"));
        Assert.True(ExclusionRules.Default.IsExcludedId("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/strestore01"));
        Assert.False(ExclusionRules.Default.IsExcludedId("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stprod"));
        Assert.False(ExclusionRules.Default.IsExcludedId("/subscriptions/s"));
    }

    [Fact]
    public void KqlFilterKeepsExcludedResourcesInAzure()
    {
        var kql = ExclusionRules.Default.KqlFilter();
        Assert.Contains("name !contains 'restore'", kql);
        Assert.Contains("resourceGroup !contains 'restore'", kql);
        Assert.Equal("", new ExclusionRules([]).KqlFilter());
    }

    [Fact]
    public void SampleEstate_RestoreResourcesAreDroppedBeforeRating()
    {
        var raw = DemoDataService.Estate();
        Assert.Contains(raw.VirtualMachines, v => v.Name == "vm-crm-restore-01");
        Assert.Contains(raw.StorageAccounts, a => a.Name == "strestorevalidation");

        var scan = DemoDataService.Scan([DemoDataService.SubProd, DemoDataService.SubDev]);
        Assert.DoesNotContain(scan.VirtualMachines, v => v.Name == "vm-crm-restore-01");
        Assert.DoesNotContain(scan.StorageAccounts, a => a.Name == "strestorevalidation");
        Assert.DoesNotContain(scan.Findings, f => f.ResourceName.Contains("restore", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(scan.Findings, f => f.ResourceGroup.Contains("restore", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(2, scan.ExcludedCount);
        Assert.Equal("'restore'", scan.ExclusionPatterns);
    }

    [Fact]
    public void ConfiguredPatternsReplaceTheDefault()
    {
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Audit:ExcludePatterns:0"] = "restore", ["Audit:ExcludePatterns:1"] = "sandbox" })
            .Build();
        var rules = ExclusionRules.FromConfiguration(config);
        Assert.True(rules.IsExcluded("vm-sandbox-1", "rg"));
        Assert.True(rules.IsExcluded("vm-1", "rg-restore"));
        Assert.Equal("'restore', 'sandbox'", rules.Description);
        Assert.Same(ExclusionRules.Default, ExclusionRules.FromConfiguration(null));
    }
}
