using System.IO.Compression;
using RateMyAzureSubscriptions.Models;
using RateMyAzureSubscriptions.Services;
using Xunit;

namespace RateMyAzureSubscriptions.Tests;

/// <summary>Summary, detailed-findings and improvement-plan reports, in HTML (preview) and Word.</summary>
public class ReportTests
{
    private static AuditReportContext Context(AuditScanResult? scan) => new()
    {
        CustomerName = "Contoso Ltd (demo)",
        TenantName = "Contoso Ltd (demo)",
        ReportAuthor = "tester",
        ScanDate = new DateTime(2026, 10, 26, 9, 0, 0),
        SubscriptionLines = ["Contoso Production (111)", "Contoso Dev/Test (222)"],
        SubscriptionNames = new(StringComparer.OrdinalIgnoreCase) { [DemoDataService.SubProd] = "Contoso Production", [DemoDataService.SubDev] = "Contoso Dev/Test" },
        Scan = scan,
    };

    [Theory]
    [InlineData(ReportKind.Summary)]
    [InlineData(ReportKind.Findings)]
    [InlineData(ReportKind.Plan)]
    public void HtmlPreview_ContainsHeadlineContent(ReportKind kind)
    {
        var scan = DemoDataService.Scan([DemoDataService.SubProd, DemoDataService.SubDev]);
        var html = AuditReportService.Html(Context(scan), kind);
        Assert.Contains("Azure Environment Audit", html);
        Assert.Contains("Contoso Ltd (demo)", html);
        Assert.Contains("Microsoft Entra ID", html);
        Assert.Contains("Identity and Access Management", html);
        if (kind == ReportKind.Plan) Assert.Contains("Priority 1", html);
        else Assert.Contains("EXCELLENT", html); // legend
        if (kind == ReportKind.Findings) Assert.Contains("Management port open to Internet", html);
        if (kind == ReportKind.Summary) Assert.Contains("prioritised improvement plan", html);
    }

    [Theory]
    [InlineData(ReportKind.Summary)]
    [InlineData(ReportKind.Findings)]
    [InlineData(ReportKind.Plan)]
    public void Docx_IsAValidPackageWithContent(ReportKind kind)
    {
        var scan = DemoDataService.Scan([DemoDataService.SubProd, DemoDataService.SubDev]);
        var bytes = AuditReportService.Docx(Context(scan), kind);
        Assert.True(bytes.Length > 2000);
        using var zip = new ZipArchive(new MemoryStream(bytes));
        var doc = zip.GetEntry("word/document.xml");
        Assert.NotNull(doc);
        using var reader = new StreamReader(doc!.Open());
        var xml = reader.ReadToEnd();
        Assert.Contains("Azure Environment Audit", xml);
        Assert.Contains("Compute", xml);
    }

    [Fact]
    public void Reports_WithoutScanStillRender()
    {
        foreach (var kind in new[] { ReportKind.Summary, ReportKind.Findings, ReportKind.Plan })
        {
            var html = AuditReportService.Html(Context(null), kind);
            Assert.Contains("No scan data", html);
            Assert.True(AuditReportService.Docx(Context(null), kind).Length > 0);
        }
    }

    [Fact]
    public void FileName_UsesCustomerKindAndDate()
    {
        var ctx = Context(null);
        Assert.Equal("ContosoLtddemo-AzureAudit-ImprovementPlan-20261026.docx", AuditReportService.FileName(ctx, ReportKind.Plan));
        Assert.Equal("ContosoLtddemo-AzureAudit-Summary-20261026.docx", AuditReportService.FileName(ctx, ReportKind.Summary));
    }

    [Theory]
    [InlineData(ReportKind.Summary)]
    [InlineData(ReportKind.Findings)]
    [InlineData(ReportKind.Plan)]
    public void SeverityFilter_LeavesHiddenFindingsOutOfTheReport(ReportKind kind)
    {
        var scan = DemoDataService.Scan([DemoDataService.SubProd, DemoDataService.SubDev]);
        var lowOnlyCategory = scan.Findings.Where(f => f.Severity == "Low").Select(f => f.Category)
            .First(c => scan.Findings.Where(f => f.Category == c).All(f => f.Severity == "Low"));
        var all = Context(scan);
        var filtered = new AuditReportContext
        {
            CustomerName = all.CustomerName, TenantName = all.TenantName, ReportAuthor = all.ReportAuthor, ScanDate = all.ScanDate,
            SubscriptionLines = all.SubscriptionLines, SubscriptionNames = all.SubscriptionNames, Scan = scan,
            VisibleSeverities = new HashSet<string> { "High", "Medium" },
        };

        var full = AuditReportService.Markdown(all, kind);
        var md = AuditReportService.Markdown(filtered, kind);
        Assert.Contains(lowOnlyCategory, full);
        Assert.DoesNotContain(lowOnlyCategory, md);
        Assert.Contains("High, Medium (Low hidden by the severity filter)", md);
        Assert.Contains("High, Medium and Low", full);
        Assert.True(md.Length < full.Length);
    }
}
