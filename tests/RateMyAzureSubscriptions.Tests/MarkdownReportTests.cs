using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using RateMyAzureSubscriptions.Components.Shared;
using RateMyAzureSubscriptions.Services;
using RateMyAzureSubscriptions.Services.Azure;
using RateMyAzureSubscriptions.Services.Reports;
using System.Text.Json;
using Xunit;

namespace RateMyAzureSubscriptions.Tests;

/// <summary>The Markdown rendering of the reports (for GitHub issues) and the Copy Markdown button.</summary>
public class MarkdownReportTests
{
    private static AuditReportContext Context() => new()
    {
        CustomerName = "Contoso Ltd (demo)", TenantName = "Contoso Ltd (demo)", ReportAuthor = "tester",
        ScanDate = new DateTime(2026, 10, 26, 9, 0, 0),
        SubscriptionLines = ["Contoso Production (111)", "Contoso Dev/Test (222)"],
        Scan = DemoDataService.Scan([DemoDataService.SubProd, DemoDataService.SubDev]),
    };

    [Theory]
    [InlineData(ReportKind.Summary)]
    [InlineData(ReportKind.Findings)]
    [InlineData(ReportKind.Plan)]
    public void Markdown_IsGitHubFlavoured(ReportKind kind)
    {
        var md = AuditReportService.Markdown(Context(), kind);
        Assert.StartsWith("# Azure Environment Audit", md);
        Assert.Contains("\n## 1. Document information\n", md);
        Assert.Contains("| **Customer** | Contoso Ltd (demo) |", md);
        Assert.Contains("|---|", md);
        if (kind != ReportKind.Plan) Assert.Contains("**Grade ", md);
        Assert.Contains("- ", md);
        Assert.DoesNotContain("<h1", md);
        Assert.DoesNotContain("<table", md);
        // Multi-line cells become <br>, never raw newlines inside a table row.
        Assert.Contains("Contoso Production (111)<br>Contoso Dev/Test (222)", md);
        if (kind == ReportKind.Plan) Assert.Contains("## 4. Priority 1", md);
    }

    [Fact]
    public void Markdown_EscapesPipesAndMarkupInCells()
    {
        var doc = new ReportDoc { Title = "T" };
        doc.Table(["A", "B"], [["x | y", "<b>not html</b>"]], "");
        doc.P("# not a heading");
        var md = MarkdownReportRenderer.Render(doc);
        Assert.Contains("| x \\| y | \\<b>not html\\</b> |", md);
        Assert.Contains("\\# not a heading", md);
    }

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

    [Fact]
    public async Task ReportModal_CopyMarkdownButton_CopiesTheCurrentReport()
    {
        using var ctx = new BunitContext();
        var credential = new global::Azure.Identity.AzureCliCredential();
        ctx.Services.AddSingleton<global::Azure.Core.TokenCredential>(credential);
        ctx.Services.AddSingleton<IAzureApi, ThrowingAzureApi>();
        ctx.Services.AddSingleton(new AuditDiscoveryService(new ThrowingAzureApi(), NullLogger<AuditDiscoveryService>.Instance));
        ctx.Services.AddScoped(_ => new AzureSubscriptionService(credential, NullLogger<AzureSubscriptionService>.Instance));
        ctx.Services.AddScoped<SessionState>();
        ctx.Services.AddScoped<AuditFlowService>();
        ctx.JSInterop.Mode = JSRuntimeMode.Loose;
        var copy = ctx.JSInterop.Setup<bool>("rmas.copy", _ => true).SetResult(true);

        var flows = ctx.Services.GetRequiredService<AuditFlowService>();
        flows.EnterDemoMode();
        flows.State.SelectedSubscriptionIds.Add(DemoDataService.SubProd);
        await flows.ScanAsync();

        var cut = ctx.Render<GradesStep>();
        cut.FindAll("button.btn").First(b => b.TextContent.Contains("Summary report")).Click();
        var button = cut.FindAll("button.btn").First(b => b.TextContent.Contains("Copy Markdown"));
        await cut.InvokeAsync(() => button.Click());

        var call = Assert.Single(copy.Invocations);
        var markdown = Assert.IsType<string>(call.Arguments[0]);
        Assert.StartsWith("# Azure Environment Audit - Summary Report", markdown);
        Assert.Contains("| **Customer** |", markdown);
        cut.WaitForAssertion(() => Assert.Contains("Copied", cut.Markup));
    }
}

/// <summary>Reports must not contain em dashes in any format (they paste badly into tickets and chat).</summary>
public class ReportPunctuationTests
{
    [Theory]
    [InlineData(ReportKind.Summary)]
    [InlineData(ReportKind.Findings)]
    [InlineData(ReportKind.Plan)]
    public void NoEmDashesInAnyFormat(ReportKind kind)
    {
        var ctx = new AuditReportContext { CustomerName = "Contoso", Scan = DemoDataService.Scan([DemoDataService.SubProd, DemoDataService.SubDev]) };
        Assert.DoesNotContain("—", AuditReportService.Html(ctx, kind));
        Assert.DoesNotContain("—", AuditReportService.Markdown(ctx, kind));
        using var zip = new System.IO.Compression.ZipArchive(new MemoryStream(AuditReportService.Docx(ctx, kind)));
        using var reader = new StreamReader(zip.GetEntry("word/document.xml")!.Open());
        Assert.DoesNotContain("—", reader.ReadToEnd());
        // and the hyphen is there where the dash used to be
        Assert.Contains("Audit - ", AuditReportService.Markdown(ctx, kind));
    }

    [Fact]
    public void ReportDoc_NormalisesEveryInput()
    {
        var doc = new ReportDoc { Title = "A — B" };
        doc.H1("H — 1").P("p — q").Note("n — m").Bullets(["x — y"]).Table(["h — h"], [["c — c"]], "e — e").Grade("A", "L — L", "s — s");
        Assert.DoesNotContain("—", MarkdownReportRenderer.Render(doc));
        Assert.Contains("# A - B", MarkdownReportRenderer.Render(doc));
    }
}
