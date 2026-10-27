namespace RateMyAzureSubscriptions.Models;

/// <summary>The six areas of the audit. Each one is scored on its own 100-point scale.</summary>
public enum AuditArea { Compute, Networking, Security, Storage, EntraId, Iam }

public static class AuditAreaExtensions
{
    public static readonly AuditArea[] All = [AuditArea.Compute, AuditArea.Networking, AuditArea.Security, AuditArea.Storage, AuditArea.EntraId, AuditArea.Iam];

    public static string Label(this AuditArea area) => area switch
    {
        AuditArea.Compute => "Compute",
        AuditArea.Networking => "Networking",
        AuditArea.Security => "Security",
        AuditArea.Storage => "Storage",
        AuditArea.EntraId => "Microsoft Entra ID",
        _ => "Identity and Access Management",
    };

    public static string ShortLabel(this AuditArea area) => area switch
    {
        AuditArea.EntraId => "Entra ID",
        AuditArea.Iam => "IAM",
        _ => area.Label(),
    };

    public static string Slug(this AuditArea area) => area switch
    {
        AuditArea.Compute => "compute",
        AuditArea.Networking => "networking",
        AuditArea.Security => "security",
        AuditArea.Storage => "storage",
        AuditArea.EntraId => "entra-id",
        _ => "iam",
    };

    public static string Icon(this AuditArea area) => area switch
    {
        AuditArea.Compute => "server",
        AuditArea.Networking => "network",
        AuditArea.Security => "shield",
        AuditArea.Storage => "storage",
        AuditArea.EntraId => "entra",
        _ => "key",
    };

    public static string Description(this AuditArea area) => area switch
    {
        AuditArea.Compute => "Review virtual machines, App Services, and other compute resources, including sizing, configuration, availability, performance, and cost optimisation.",
        AuditArea.Networking => "Assess virtual networks, subnets, network security groups, routing, connectivity, private endpoints, and network security configurations.",
        AuditArea.Security => "Review Microsoft Defender for Cloud recommendations, security posture, policies, encryption, logging, monitoring, and potential vulnerabilities.",
        AuditArea.Storage => "Assess storage accounts, access controls, redundancy, encryption, lifecycle management, and configuration best practices.",
        AuditArea.EntraId => "Review tenant-level configuration, Conditional Access policies, authentication methods, MFA enforcement, and identity security settings.",
        _ => "Review Azure RBAC assignments, privileged access, managed identities, service principals, and adherence to least-privilege principles.",
    };

    /// <summary>Tenant-wide areas are assessed once per tenant rather than per subscription.</summary>
    public static bool IsTenantWide(this AuditArea area) => area == AuditArea.EntraId;
}
