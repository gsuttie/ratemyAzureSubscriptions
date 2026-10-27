using System.Text;

namespace RateMyAzureSubscriptions.Services.Reports;

/// <summary>Renders a ReportDoc as GitHub-flavoured Markdown (for issues, wikis and pull requests).</summary>
public static class MarkdownReportRenderer
{
    public static string Render(ReportDoc doc)
    {
        var sb = new StringBuilder();
        sb.Append("# ").AppendLine(doc.Title).AppendLine();
        foreach (var block in doc.Blocks)
            sb.Append(Render(block));
        return sb.ToString().TrimEnd() + Environment.NewLine;
    }

    private static string Render(ReportBlock block) => block switch
    {
        HeadingBlock h => $"{(h.Level == 1 ? "##" : "###")} {h.Text}\n\n",
        ParaBlock p => Para(p),
        NoteBlock n => $"> _{Inline(n.Text)}_\n\n",
        BulletBlock b => string.Concat(b.Items.Select(i => $"- {Inline(i)}\n")) + "\n",
        TableBlock t => t.Rows.Count == 0 ? $"_{Inline(t.EmptyText)}_\n\n" : Table(t),
        GradeBlock g => $"**Grade {g.Grade} - {g.Label}**  \n{Inline(g.Summary)}\n\n",
        LegendBlock => Legend(),
        _ => ""
    };

    private static string Para(ParaBlock p)
    {
        var text = Inline(p.Text).Replace("\n", "  \n");
        return (p.Bold ? $"**{text}**" : text) + "\n\n";
    }

    private static string Legend()
    {
        var sb = new StringBuilder("| Grade | Label | Meaning |\n|---|---|---|\n");
        foreach (var (grade, label, description) in AuditRatingService.Legend)
            sb.Append($"| **{grade}** | {label} | {Cell(ReportText.Plain(description))} |\n");
        return sb.Append('\n').ToString();
    }

    private static string Table(TableBlock t)
    {
        var sb = new StringBuilder();
        var cols = Math.Max(t.Headers?.Length ?? 0, t.Rows.Max(r => r.Length));
        if (t.Headers is { Length: > 0 })
        {
            sb.Append("| ").Append(string.Join(" | ", t.Headers.Select(Cell))).Append(" |\n");
        }
        else
        {
            // GitHub tables need a header row; a key/value table uses an empty one.
            sb.Append('|').Append(string.Concat(Enumerable.Repeat("   |", cols))).Append('\n');
        }
        sb.Append('|').Append(string.Concat(Enumerable.Repeat("---|", cols))).Append('\n');
        for (var r = 0; r < t.Rows.Count; r++)
        {
            var cells = t.Rows[r].Select((c, i) =>
            {
                var text = Cell(c);
                var coloured = t.CellColors is not null && r < t.CellColors.Count && i < t.CellColors[r].Length && t.CellColors[r][i] is not null;
                return t.FirstColHeader && i == 0 || coloured ? $"**{text}**" : text;
            }).ToList();
            while (cells.Count < cols) cells.Add("");
            sb.Append("| ").Append(string.Join(" | ", cells)).Append(" |\n");
        }
        return sb.Append('\n').ToString();
    }

    /// <summary>Escapes a table cell: pipes break columns and newlines break rows.</summary>
    private static string Cell(string s) => Inline(s).Replace("|", "\\|").Replace("\r", "").Replace("\n", "<br>");

    /// <summary>Keeps Markdown from reading plain text as markup (leading # or * and HTML-ish brackets).</summary>
    private static string Inline(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var text = s.Replace("<", "\\<");
        if (text.StartsWith('#') || text.StartsWith('*') || text.StartsWith('-') || text.StartsWith('>')) text = "\\" + text;
        return text;
    }
}
