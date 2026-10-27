namespace RateMyAzureSubscriptions.Services.Reports;

/// <summary>
/// Renderer-agnostic report content. The same document model drives the on-screen HTML preview, the
/// downloadable Word file and the Markdown copy, so every format carries identical content.
/// All text is normalised on the way in (see <see cref="ReportText.Plain"/>): em dashes become hyphens.
/// </summary>
public sealed class ReportDoc
{
    private string _title = string.Empty;
    public string Title { get => _title; init => _title = ReportText.Plain(value); }
    public List<ReportBlock> Blocks { get; } = new();

    public ReportDoc H1(string text) { Blocks.Add(new HeadingBlock(1, ReportText.Plain(text))); return this; }
    public ReportDoc H2(string text) { Blocks.Add(new HeadingBlock(2, ReportText.Plain(text))); return this; }
    public ReportDoc P(string text, bool bold = false, string? color = null) { Blocks.Add(new ParaBlock(ReportText.Plain(text), bold, color)); return this; }
    public ReportDoc Note(string text) { Blocks.Add(new NoteBlock(ReportText.Plain(text))); return this; }
    public ReportDoc Bullets(IEnumerable<string> items) { Blocks.Add(new BulletBlock(items.Select(ReportText.Plain).ToList())); return this; }
    public ReportDoc Table(string[]? headers, List<string[]> rows, string emptyText, List<string?[]>? cellColors = null, bool firstColHeader = false)
    {
        Blocks.Add(new TableBlock(headers?.Select(ReportText.Plain).ToArray(), rows.Select(r => r.Select(ReportText.Plain).ToArray()).ToList(), ReportText.Plain(emptyText), cellColors, firstColHeader));
        return this;
    }
    public ReportDoc Grade(string grade, string label, string summary) { Blocks.Add(new GradeBlock(grade, ReportText.Plain(label), ReportText.Plain(summary))); return this; }
    public ReportDoc Legend() { Blocks.Add(new LegendBlock()); return this; }
}

/// <summary>Text normalisation shared by the document model and the renderers.</summary>
public static class ReportText
{
    /// <summary>Replaces em dashes with a plain hyphen so reports paste cleanly into tickets and chat.</summary>
    public static string Plain(string? text) => string.IsNullOrEmpty(text) ? string.Empty : text.Replace('—', '-');
}

public abstract record ReportBlock;
public sealed record HeadingBlock(int Level, string Text) : ReportBlock;
public sealed record ParaBlock(string Text, bool Bold = false, string? Color = null) : ReportBlock;
public sealed record NoteBlock(string Text) : ReportBlock;
public sealed record BulletBlock(List<string> Items) : ReportBlock;
public sealed record TableBlock(string[]? Headers, List<string[]> Rows, string EmptyText, List<string?[]>? CellColors, bool FirstColHeader) : ReportBlock;
/// <summary>Headline grade tile: big coloured letter, label and a one-line summary.</summary>
public sealed record GradeBlock(string Grade, string Label, string Summary) : ReportBlock;
/// <summary>The full-colour A-F legend.</summary>
public sealed record LegendBlock : ReportBlock;
