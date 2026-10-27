using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using RateMyAzureSubscriptions.Components.Shared;
using RateMyAzureSubscriptions.Models;
using RateMyAzureSubscriptions.Services;
using RateMyAzureSubscriptions.Services.Azure;
using System.Text.Json;
using Xunit;

namespace RateMyAzureSubscriptions.Tests;

/// <summary>Rendering tests for the UI components, driven by the sample estate (no Azure).</summary>
public class ComponentTests : BunitContext
{
    /// <summary>An IAzureApi that must never be called: sample-data mode keeps everything local.</summary>
    private sealed class ThrowingAzureApi : IAzureApi
    {
        private static Exception Fail() => new InvalidOperationException("Azure must not be called in demo mode");
        public Task<List<JsonElement>> QueryResourceGraphAsync(string query, IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default) => throw Fail();
        public Task<List<JsonElement>> GetArmListAsync(string url, string? tenantId, CancellationToken ct = default) => throw Fail();
        public Task<JsonElement?> GetArmAsync(string url, string? tenantId, CancellationToken ct = default) => throw Fail();
        public Task<List<JsonElement>> GetGraphListAsync(string relativeUrl, string? tenantId, CancellationToken ct = default, bool consistencyLevelEventual = false) => throw Fail();
        public Task<JsonElement?> GetGraphAsync(string relativeUrl, string? tenantId, CancellationToken ct = default) => throw Fail();
        public Task<List<JsonElement>> PostGraphAsync(string relativeUrl, string jsonBody, string? tenantId, CancellationToken ct = default) => throw Fail();
    }

    private AuditFlowService Flows { get; }

    public ComponentTests()
    {
        var credential = new global::Azure.Identity.AzureCliCredential();
        Services.AddSingleton<global::Azure.Core.TokenCredential>(credential);
        Services.AddSingleton<IAzureApi, ThrowingAzureApi>();
        Services.AddSingleton(new AuditDiscoveryService(new ThrowingAzureApi(), NullLogger<AuditDiscoveryService>.Instance));
        Services.AddScoped(_ => new AzureSubscriptionService(credential, NullLogger<AzureSubscriptionService>.Instance));
        Services.AddScoped<SessionState>();
        Services.AddScoped<AuditFlowService>();
        JSInterop.Mode = JSRuntimeMode.Loose;

        Flows = Services.GetRequiredService<AuditFlowService>();
        Flows.EnterDemoMode();
    }

    private async Task ScanAsync()
    {
        Flows.State.SelectedSubscriptionIds.Add(DemoDataService.SubProd);
        Flows.State.SelectedSubscriptionIds.Add(DemoDataService.SubDev);
        await Flows.ScanAsync();
    }

    [Fact]
    public void GradeBadge_RendersLetterAndColour()
    {
        var cut = Render<GradeBadge>(p => p.Add(x => x.Grade, "B").Add(x => x.Large, true));
        var span = cut.Find("span.grade-badge");
        Assert.Equal("B", span.TextContent);
        Assert.Contains("lg", span.ClassName);
        Assert.Contains("#7CB342", span.GetAttribute("style"));
        Assert.Contains("Good", span.GetAttribute("title"));
    }

    [Fact]
    public void StepBar_LocksLaterStepsUntilScanned()
    {
        var cut = Render<StepBar>(p => p.Add(x => x.Current, "scope").Add(x => x.HasScan, false));
        Assert.Equal(2, cut.FindAll("li.step.locked").Count);
        cut = Render<StepBar>(p => p.Add(x => x.Current, "grades").Add(x => x.HasScan, true));
        Assert.Empty(cut.FindAll("li.step.locked"));
        Assert.Single(cut.FindAll("li.step.done"));
    }

    [Fact]
    public void ScopeStep_ListsSampleSubscriptionsAndCounts()
    {
        var cut = Render<ScopeStep>();
        cut.WaitForAssertion(() => Assert.Equal(2, cut.FindAll("li.sub-row").Count));
        Assert.Contains("Contoso Production", cut.Markup);
        cut.WaitForAssertion(() => Assert.Contains("86 resources", cut.Markup));
    }

    [Fact]
    public async Task GradesStep_ShowsSixAreasFindingsAndOpensWeakest()
    {
        await ScanAsync();
        var cut = Render<GradesStep>();
        Assert.Equal(6, cut.FindAll("article.rating").Count);
        Assert.Single(cut.FindAll("article.rating.open"));
        Assert.Contains("Microsoft Entra ID", cut.Markup);
        Assert.Contains("Score breakdown", cut.Markup);
        Assert.Contains("How to improve", cut.Markup);
        Assert.Contains("Grade capped", cut.Markup);

        // Expand a second area and check its inventory renders.
        var rows = cut.FindAll("button.rating-row");
        rows[0].Click();
        rows = cut.FindAll("button.rating-row");
        Assert.True(cut.FindAll("article.rating.open").Count >= 1);
        Assert.Contains("Inventory", cut.Markup);
    }

    [Fact]
    public async Task GradesStep_HowToFixAndScriptButtons()
    {
        await ScanAsync();
        var cut = Render<GradesStep>();
        // Open every area so findings from all six are on screen.
        while (cut.FindAll("article.rating:not(.open) button.rating-row") is { Count: > 0 } closed)
            closed[0].Click(); // re-query after every render: handles go stale

        Assert.Equal(6, cut.FindAll("article.rating.open").Count);
        var fixButtons = cut.FindAll("button.link").Where(b => b.TextContent.Contains("How to fix")).ToList();
        Assert.NotEmpty(fixButtons);
        fixButtons[0].Click();
        Assert.Contains("Hide fix", cut.Markup);
        Assert.NotEmpty(cut.FindAll("div.fix"));

        var scriptButtons = cut.FindAll("button.link").Where(b => b.TextContent.Contains("Script")).ToList();
        Assert.NotEmpty(scriptButtons);
        scriptButtons[0].Click();
        Assert.Contains("Fix script", cut.Markup);
        Assert.Contains("az ", cut.Find("pre.script").TextContent);
    }

    [Fact]
    public async Task PlanStep_GroupsByPriorityAndFiltersByArea()
    {
        await ScanAsync();
        var cut = Render<PlanStep>();
        Assert.Contains("P1", cut.Markup);
        Assert.Contains("Fix first", cut.Markup);
        Assert.Contains("Quick wins", cut.Markup);
        var total = cut.FindAll("tr.policy-row").Count;
        Assert.True(total > 3);

        var storageChip = cut.FindAll("button.chip-btn").First(b => b.TextContent.Contains("Storage"));
        storageChip.Click();
        Assert.True(cut.FindAll("tr.policy-row").Count < total);
        Assert.DoesNotContain("Management port open to Internet", cut.Markup);

        cut.FindAll("tr.policy-row")[0].Click();
        Assert.NotEmpty(cut.FindAll("tr.policy-detail-row"));
    }

    [Fact]
    public async Task ReportModal_RendersPreviewAndSwitchesTabs()
    {
        await ScanAsync();
        var cut = Render<GradesStep>();
        cut.FindAll("button.btn").First(b => b.TextContent.Contains("Summary report")).Click();
        Assert.Contains("report-preview", cut.Markup);
        Assert.Contains("Summary Report", cut.Markup);
        cut.FindAll("button.tab").First(b => b.TextContent.Contains("Improvement plan")).Click();
        Assert.Contains("Prioritised Improvement Plan", cut.Markup);
    }

    [Fact]
    public async Task GradesStep_AuditThisArea_MergesOnDemand()
    {
        Flows.State.SelectedSubscriptionIds.Add(DemoDataService.SubProd);
        Flows.State.SelectedAreas.Clear();
        Flows.State.SelectedAreas.Add(AuditArea.Compute);
        await Flows.ScanAsync();
        var cut = Render<GradesStep>();
        Assert.Contains("Audit remaining 5 areas", cut.Markup);
        var buttons = cut.FindAll("button").Where(b => b.TextContent.Contains("Audit this area")).ToList();
        Assert.Equal(5, buttons.Count);
        await cut.InvokeAsync(() => buttons[0].Click());
        cut.WaitForAssertion(() => Assert.Contains("Audit remaining 4 areas", cut.Markup), TimeSpan.FromSeconds(5));
        Assert.Equal(2, Flows.State.Scan!.AssessedAreas.Count);
    }

    [Fact]
    public void ScopeStep_ShowsAreaPicker()
    {
        var cut = Render<ScopeStep>();
        cut.WaitForAssertion(() => Assert.Equal(6, cut.FindAll("button.area-chip").Count));
        Assert.Equal(6, cut.FindAll("button.area-chip.active").Count);
        cut.FindAll("button.area-chip")[0].Click();
        Assert.Equal(5, cut.FindAll("button.area-chip.active").Count);
        Assert.Contains("5 areas", cut.Markup);
    }

    [Fact]
    public async Task GradesStep_ShowsWhyASourceFailed_NextToItsArea()
    {
        await ScanAsync();
        var scan = Flows.State.Scan!;
        scan.Issues.Add(new DataIssue
        {
            Area = AuditArea.EntraId, Source = "Authentication methods policy",
            Reason = "Permission denied (HTTP 403): the signed-in identity is not allowed to read this",
            Needs = "Microsoft Graph Policy.Read.All (Global Reader)",
            Impact = "Authentication methods rated as unknown (2 of 4 points).",
            Fix = "Ask a Global Administrator to assign the Global Reader role, then run az login again.",
            Detail = "HTTP 403: accessDenied",
        });
        AuditRatingService.AssessAll(scan);

        var cut = Render<GradesStep>();
        Assert.Contains("1 source could not be read", cut.Markup);
        Assert.Contains("Authentication methods policy", cut.Markup);
        Assert.Contains("Permission denied (HTTP 403)", cut.Markup);
        cut.FindAll("div.issue button.link").First().Click();
        Assert.Contains("Global Reader", cut.Markup);
        Assert.Contains("az login", cut.Markup);
        Assert.Contains("HTTP 403: accessDenied", cut.Markup);
    }

    [Fact]
    public async Task GradesStep_WithoutScan_PromptsForScope()
    {
        var cut = Render<GradesStep>();
        Assert.Contains("No scan yet", cut.Markup);
        await Task.CompletedTask;
    }
}

/// <summary>The High / Medium / Low checkboxes on the Grades and Improvement plan steps.</summary>
public class SeverityFilterTests : BunitContext
{
    private sealed class ThrowingAzureApi : IAzureApi
    {
        private static Exception Fail() => new InvalidOperationException("Azure must not be called in demo mode");
        public Task<List<JsonElement>> QueryResourceGraphAsync(string query, IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default) => throw Fail();
        public Task<List<JsonElement>> GetArmListAsync(string url, string? tenantId, CancellationToken ct = default) => throw Fail();
        public Task<JsonElement?> GetArmAsync(string url, string? tenantId, CancellationToken ct = default) => throw Fail();
        public Task<List<JsonElement>> GetGraphListAsync(string relativeUrl, string? tenantId, CancellationToken ct = default, bool consistencyLevelEventual = false) => throw Fail();
        public Task<JsonElement?> GetGraphAsync(string relativeUrl, string? tenantId, CancellationToken ct = default) => throw Fail();
        public Task<List<JsonElement>> PostGraphAsync(string relativeUrl, string jsonBody, string? tenantId, CancellationToken ct = default) => throw Fail();
    }

    private AuditFlowService Flows { get; }

    public SeverityFilterTests()
    {
        var credential = new global::Azure.Identity.AzureCliCredential();
        Services.AddSingleton<global::Azure.Core.TokenCredential>(credential);
        Services.AddSingleton<IAzureApi, ThrowingAzureApi>();
        Services.AddSingleton(new AuditDiscoveryService(new ThrowingAzureApi(), NullLogger<AuditDiscoveryService>.Instance));
        Services.AddScoped(_ => new AzureSubscriptionService(credential, NullLogger<AzureSubscriptionService>.Instance));
        Services.AddScoped<SessionState>();
        Services.AddScoped<AuditFlowService>();
        JSInterop.Mode = JSRuntimeMode.Loose;
        Flows = Services.GetRequiredService<AuditFlowService>();
        Flows.EnterDemoMode();
        Flows.State.SelectedSubscriptionIds.Add(DemoDataService.SubProd);
        Flows.State.SelectedSubscriptionIds.Add(DemoDataService.SubDev);
    }

    [Fact]
    public async Task PlanStep_UntickingLowHidesLowFindings_AndPersistsToGradesStep()
    {
        await Flows.ScanAsync();
        var scan = Flows.State.Scan!;
        var lows = scan.Findings.Count(f => f.Severity == "Low");
        Assert.True(lows > 0);

        var cut = Render<PlanStep>();
        Assert.Equal(3, cut.FindAll(".sev-filter input[type=checkbox]").Count);
        Assert.Contains("P3", cut.Markup);
        var rowsBefore = cut.FindAll("tr.policy-row").Count;

        cut.FindAll(".sev-filter input[type=checkbox]")[2].Change(false); // Low
        Assert.DoesNotContain("Low", Flows.State.VisibleSeverities);
        Assert.True(cut.FindAll("tr.policy-row").Count < rowsBefore);
        Assert.Contains("Nothing at this priority", cut.Markup); // P3 is empty once Low is hidden
        Assert.Contains("Show all", cut.Markup);

        // The choice is session-wide: the Grades step hides the same findings and says so.
        var grades = Render<GradesStep>();
        Assert.Contains("hidden)", grades.Markup);
        Assert.DoesNotContain("sev low", grades.FindAll("ul.findings .sev").Select(e => e.ClassName.ToLowerInvariant()));

        grades.FindAll("button.link").First(b => b.TextContent.Contains("Show all")).Click();
        Assert.Equal(3, Flows.State.VisibleSeverities.Count);
        Assert.DoesNotContain("hidden)", grades.Markup);
    }
}
