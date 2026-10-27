namespace RateMyAzureSubscriptions.Models;

/// <summary>A-F rating for one audit area across the scanned subscriptions.</summary>
public sealed class AreaRating
{
    public AuditArea Area { get; set; }

    /// <summary>Total score out of 100 across the area's categories.</summary>
    public int Score { get; set; }

    /// <summary>"A" (best) to "F" (worst), after caps.</summary>
    public string Grade { get; set; } = "F";
    public string GradeLabel { get; set; } = string.Empty;

    /// <summary>Why the grade was capped below what the raw score would give; null when uncapped.</summary>
    public string? CapReason { get; set; }

    public List<RatingCategory> Categories { get; set; } = new();

    /// <summary>Actions that raise the score, largest gain first.</summary>
    public List<Improvement> Improvements { get; set; } = new();

    /// <summary>How many resources (or tenant settings) the area was rated on.</summary>
    public int ResourceCount { get; set; }

    /// <summary>One-line description of what was assessed, e.g. "12 VMs, 4 App Services".</summary>
    public string ScopeSummary { get; set; } = string.Empty;

    /// <summary>True when nothing could be assessed (no resources, or the data could not be read).</summary>
    public bool NotAssessed { get; set; }
    public string? NotAssessedReason { get; set; }

    /// <summary>Sources that could not be read for this area, with the reason and what it needs.</summary>
    public List<DataIssue> Issues { get; set; } = new();
}

/// <summary>A data source the scan could not read, explained for the person looking at the grade.</summary>
public sealed class DataIssue
{
    public AuditArea Area { get; set; }
    /// <summary>What was being read, e.g. "Conditional Access policies".</summary>
    public string Source { get; set; } = string.Empty;
    /// <summary>Plain-language reason, e.g. "Permission denied (HTTP 403)".</summary>
    public string Reason { get; set; } = string.Empty;
    /// <summary>What access would fix it, e.g. "Microsoft Graph Policy.Read.All (Global Reader)".</summary>
    public string Needs { get; set; } = string.Empty;
    /// <summary>How the rating treated the gap, e.g. "Rated as unknown (half points)".</summary>
    public string Impact { get; set; } = string.Empty;
    /// <summary>Steps (and command, where there is one) that make the source readable.</summary>
    public string Fix { get; set; } = string.Empty;
    /// <summary>The raw error, shortened, for support.</summary>
    public string Detail { get; set; } = string.Empty;
}

public sealed class RatingCategory
{
    public string Name { get; set; } = string.Empty;
    public int Earned { get; set; }
    public int Possible { get; set; }
    public List<string> Details { get; set; } = new();
}

public sealed class Improvement
{
    public string Action { get; set; } = string.Empty;
    public int PointsGained { get; set; }

    /// <summary>Grade after applying just this improvement (including any cap it lifts).</summary>
    public string ResultingGrade { get; set; } = string.Empty;
}

/// <summary>A report-only finding with remediation guidance, effort and (where possible) a fix script.</summary>
public sealed class AuditFinding
{
    public AuditArea Area { get; set; }

    /// <summary>High, Medium or Low.</summary>
    public string Severity { get; set; } = "Medium";
    public string Category { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string ResourceName { get; set; } = string.Empty;
    public string ResourceId { get; set; } = string.Empty;
    public string ResourceGroup { get; set; } = string.Empty;
    public string SubscriptionId { get; set; } = string.Empty;
    public string Fix { get; set; } = string.Empty;

    /// <summary>Low, Medium or High: how much work the fix is.</summary>
    public string Effort { get; set; } = "Medium";

    /// <summary>Azure CLI / PowerShell snippet that applies the fix, or null when there is no safe one-liner.</summary>
    public string? Script { get; set; }

    public string Key => $"{ResourceId}|{Category}|{Message}";

    /// <summary>P1 for High, P2 for Medium, P3 for Low.</summary>
    public int Priority => Severity switch { "High" => 1, "Medium" => 2, _ => 3 };
}
