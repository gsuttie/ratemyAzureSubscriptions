using RateMyAzureSubscriptions.Models;
using RateMyAzureSubscriptions.Services.Assessment;

namespace RateMyAzureSubscriptions.Services;

/// <summary>
/// The A-F engine. Every audit area is scored on its own 100-point scale from weighted categories,
/// mapped to a grade (A >= 90, B >= 75, C >= 60, D >= 45, E >= 30, F below), with hard caps so a
/// good score cannot hide a critical gap. The area assessors decide what earns points; this class
/// owns the grade bands, the colours and the overall roll-up.
/// </summary>
public static class AuditRatingService
{
    /// <summary>Grade letter for a raw 0-100 score, before caps.</summary>
    public static string GradeForScore(int score) => score switch
    {
        >= 90 => "A",
        >= 75 => "B",
        >= 60 => "C",
        >= 45 => "D",
        >= 30 => "E",
        _ => "F"
    };

    public static string LabelForGrade(string grade) => grade switch
    {
        "A" => "Excellent",
        "B" => "Good",
        "C" => "Average",
        "D" => "Below Average",
        "E" => "Poor",
        "F" => "Unacceptable",
        _ => "Not assessed"
    };

    /// <summary>Traffic-light colour for a grade (hex, with leading '#'). Green to dark red; grey when not assessed.</summary>
    public static string ColorForGrade(string grade) => grade switch
    {
        "A" => "#388E3C",
        "B" => "#7CB342",
        "C" => "#FBC02D",
        "D" => "#F57C00",
        "E" => "#E64A19",
        "F" => "#C62828",
        _ => "#78909C"
    };

    /// <summary>The A-F legend shown in the app and in the reports.</summary>
    public static readonly (string Grade, string Label, string Description)[] Legend =
    [
        ("A", "EXCELLENT", "Outstanding — exceeds expectations"),
        ("B", "GOOD", "Above average — meets most expectations"),
        ("C", "AVERAGE", "Satisfactory — meets basic expectations"),
        ("D", "BELOW AVERAGE", "Below expectations — needs improvement"),
        ("E", "POOR", "Far below expectations — significant improvement needed"),
        ("F", "UNACCEPTABLE", "Unacceptable — does not meet minimum requirements"),
    ];

    /// <summary>The worse (further down the alphabet) of two grades.</summary>
    public static string WorstGrade(string a, string b) => string.CompareOrdinal(a, b) >= 0 ? a : b;

    /// <summary>The weakest assessed area.</summary>
    public static AreaRating? Worst(IEnumerable<AreaRating> ratings) =>
        ratings.Where(r => !r.NotAssessed).OrderByDescending(r => r.Grade, StringComparer.Ordinal).ThenBy(r => r.Score).FirstOrDefault();

    /// <summary>Overall grade: the letter for the average score of the assessed areas, never better than one grade above the weakest area.</summary>
    public static string OverallGrade(AuditScanResult scan)
    {
        var worst = Worst(scan.Ratings);
        if (worst is null) return "–";
        var avgGrade = GradeForScore(scan.OverallScore);
        // One weak area must still drag the overall down: never more than one band above the weakest.
        var floor = (char)Math.Max('A', worst.Grade[0] - 1);
        return WorstGrade(avgGrade, floor.ToString());
    }

    /// <summary>Runs every area assessor over the scan and stores ratings and findings on it.</summary>
    public static void AssessAll(AuditScanResult scan)
    {
        var findings = new FindingSink();
        const string pending = "Not audited yet — audit this area from the Grades step.";
        scan.Ratings =
        [
            scan.AssessedAreas.Contains(AuditArea.Compute) ? ComputeAssessor.Assess(scan, findings) : RatingBuilder.NotAssessed(AuditArea.Compute, pending),
            scan.AssessedAreas.Contains(AuditArea.Networking) ? NetworkingAssessor.Assess(scan, findings) : RatingBuilder.NotAssessed(AuditArea.Networking, pending),
            scan.AssessedAreas.Contains(AuditArea.Security) ? SecurityAssessor.Assess(scan, findings) : RatingBuilder.NotAssessed(AuditArea.Security, pending),
            scan.AssessedAreas.Contains(AuditArea.Storage) ? StorageAssessor.Assess(scan, findings) : RatingBuilder.NotAssessed(AuditArea.Storage, pending),
            scan.AssessedAreas.Contains(AuditArea.EntraId) ? EntraAssessor.Assess(scan, findings) : RatingBuilder.NotAssessed(AuditArea.EntraId, pending),
            scan.AssessedAreas.Contains(AuditArea.Iam) ? IamAssessor.Assess(scan, findings) : RatingBuilder.NotAssessed(AuditArea.Iam, pending),
        ];
        foreach (var r in scan.Ratings)
            r.Issues = scan.Issues.Where(i => i.Area == r.Area).ToList();
        scan.Findings = findings.Items
            .OrderBy(f => f.Priority)
            .ThenBy(f => f.Area)
            .ThenBy(f => f.ResourceName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static int SeverityOrder(string severity) => severity switch { "High" => 0, "Medium" => 1, _ => 2 };
    public static int EffortOrder(string effort) => effort switch { "Low" => 0, "Medium" => 1, _ => 2 };
}

/// <summary>Accumulates categories, caps and improvements for one area and turns them into an AreaRating.</summary>
internal sealed class RatingBuilder
{
    private readonly AuditArea _area;
    private readonly List<RatingCategory> _categories = new();
    private readonly List<(string Key, string MaxGrade, string Reason)> _caps = new();
    private readonly List<(Improvement Item, string? LiftsCapKey)> _improvements = new();

    public RatingBuilder(AuditArea area) => _area = area;

    public RatingCategory Category(string name, int possible)
    {
        var c = new RatingCategory { Name = name, Possible = possible };
        _categories.Add(c);
        return c;
    }

    public void Cap(string key, string maxGrade, string reason) => _caps.Add((key, maxGrade, reason));

    public void Improve(string action, int points, string? liftsCapKey = null)
    {
        if (points > 0)
            _improvements.Add((new Improvement { Action = action, PointsGained = points }, liftsCapKey));
    }

    /// <summary>Awards a pro-rated share of <paramref name="pts"/>; full marks when there is nothing to assess.</summary>
    public static int Prorate(int pts, int ok, int total)
    {
        if (total <= 0) return pts;
        var earned = (int)Math.Round(pts * (double)ok / total);
        if (ok > 0 && ok < total) earned = Math.Clamp(earned, 1, pts - 1);
        return earned;
    }

    /// <summary>
    /// Scores one check: pro-rates the points, records the detail line and queues the improvement for the gap.
    /// </summary>
    public int Check(RatingCategory category, int pts, int ok, int total, string detail, string improvement, string? liftsCapKey = null)
    {
        var earned = Prorate(pts, ok, total);
        category.Earned += earned;
        category.Details.Add(detail);
        if (earned < pts) Improve(improvement, pts - earned, liftsCapKey);
        return earned;
    }

    public AreaRating Build(int resourceCount, string scopeSummary)
    {
        var rating = new AreaRating
        {
            Area = _area,
            Categories = _categories,
            ResourceCount = resourceCount,
            ScopeSummary = scopeSummary,
        };

        rating.Score = Math.Clamp(_categories.Sum(c => c.Earned), 0, 100);
        var scoreGrade = AuditRatingService.GradeForScore(rating.Score);
        var finalGrade = _caps.Aggregate(scoreGrade, (g, cap) => AuditRatingService.WorstGrade(g, cap.MaxGrade));

        rating.Grade = finalGrade;
        rating.GradeLabel = AuditRatingService.LabelForGrade(finalGrade);
        rating.CapReason = finalGrade != scoreGrade
            ? _caps.Where(c => c.MaxGrade == finalGrade).Select(c => c.Reason).FirstOrDefault()
            : null;

        foreach (var (item, liftsCapKey) in _improvements)
        {
            var newScore = Math.Min(100, rating.Score + item.PointsGained);
            var remainingCaps = _caps.Where(c => c.Key != liftsCapKey);
            item.ResultingGrade = remainingCaps.Aggregate(AuditRatingService.GradeForScore(newScore), (g, cap) => AuditRatingService.WorstGrade(g, cap.MaxGrade));
        }
        rating.Improvements = _improvements.Select(i => i.Item).OrderByDescending(i => i.PointsGained).ToList();
        return rating;
    }

    public static AreaRating NotAssessed(AuditArea area, string reason) => new()
    {
        Area = area,
        Grade = "–",
        GradeLabel = "Not assessed",
        NotAssessed = true,
        NotAssessedReason = reason,
        ScopeSummary = reason,
    };
}
