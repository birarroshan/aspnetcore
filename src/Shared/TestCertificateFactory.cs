// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

#nullable enable

namespace Microsoft.AspNetCore.InternalTesting;

internal static class TestCertificateFactory
{
    internal const string TestCertificatePassword = "testPassword";

    private const int AspNetHttpsCertificateVersion = 6;
    private const string AspNetHttpsOid = "1.3.6.1.4.1.311.84.1.1";
    private const string AspNetHttpsOidFriendlyName = "ASP.NET Core HTTPS development certificate";
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";
    private const string ServerAuthenticationOidFriendlyName = "Server Authentication";
    private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";
    private const string ClientAuthenticationOidFriendlyName = "Client Authentication";
    private const string CodeSigningOid = "1.3.6.1.5.5.7.3.3";
    private const string CodeSigningOidFriendlyName = "Code Signing";

    internal static Oid ServerAuthentication => new(ServerAuthenticationOid, ServerAuthenticationOidFriendlyName);

    internal static Oid ClientAuthentication => new(ClientAuthenticationOid, ClientAuthenticationOidFriendlyName);

    internal static Oid CodeSigning => new(CodeSigningOid, CodeSigningOidFriendlyName);

    internal static X509Certificate2 CreateRsaCertificate(
        string subjectName = "CN=localhost",
        Oid[]? enhancedKeyUsages = null,
        bool includeSubjectAlternativeName = false,
        bool includeAspNetHttpsExtension = false,
        bool includeBasicConstraints = false,
        bool includeKeyUsage = true,
        X509KeyUsageFlags keyUsage = X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature,
        bool keyUsageCritical = true,
        bool enhancedKeyUsageCritical = false,
        bool subjectAlternativeNameCritical = false,
        Action<SubjectAlternativeNameBuilder>? configureSubjectAlternativeNames = null)
    {
        using var key = RSA.Create();
        key.KeySize = 2048;
        var request = new CertificateRequest(new X500DistinguishedName(subjectName), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return CreateCertificate(
            request,
            enhancedKeyUsages,
            includeSubjectAlternativeName,
            includeAspNetHttpsExtension,
            includeBasicConstraints,
            includeKeyUsage,
            keyUsage,
            keyUsageCritical,
            enhancedKeyUsageCritical,
            subjectAlternativeNameCritical,
            configureSubjectAlternativeNames);
    }

    internal static X509Certificate2 CreateEcdsaCertificate(
        string subjectName = "CN=localhost",
        Oid[]? enhancedKeyUsages = null,
        bool includeSubjectAlternativeName = false,
        bool includeKeyUsage = true,
        X509KeyUsageFlags keyUsage = X509KeyUsageFlags.DigitalSignature,
        bool keyUsageCritical = true,
        bool enhancedKeyUsageCritical = false,
        bool subjectAlternativeNameCritical = false,
        Action<SubjectAlternativeNameBuilder>? configureSubjectAlternativeNames = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(new X500DistinguishedName(subjectName), key, HashAlgorithmName.SHA256);

        return CreateCertificate(
            request,
            enhancedKeyUsages,
            includeSubjectAlternativeName,
            includeAspNetHttpsExtension: false,
            includeBasicConstraints: false,
            includeKeyUsage,
            keyUsage,
            keyUsageCritical,
            enhancedKeyUsageCritical,
            subjectAlternativeNameCritical,
            configureSubjectAlternativeNames);
    }

    internal static X509Certificate2 CreatePublicKeyOnlyCertificate(X509Certificate2 certificate)
    {
        return new X509Certificate2(certificate.Export(X509ContentType.Cert));
    }

    internal static void WritePfxFile(X509Certificate2 certificate, string path, string password = TestCertificatePassword)
    {
        var directory = Path.GetDirectoryName(path) ??
            throw new InvalidOperationException($"Cannot determine certificate directory for '{path}'.");
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(path, certificate.Export(X509ContentType.Pfx, password));
    }

    internal static void ConfigureLocalhostSubjectAlternativeNames(SubjectAlternativeNameBuilder sanBuilder)
    {
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddIpAddress(IPAddress.Loopback);
        sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
    }

    internal static void ConfigureAspNetHttpsSubjectAlternativeNames(SubjectAlternativeNameBuilder sanBuilder)
    {
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddDnsName("*.dev.localhost");
        sanBuilder.AddDnsName("*.dev.internal");
        sanBuilder.AddDnsName("host.docker.internal");
        sanBuilder.AddDnsName("host.containers.internal");
        sanBuilder.AddIpAddress(IPAddress.Loopback);
        sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
    }

    private static X509Certificate2 CreateCertificate(
        CertificateRequest request,
        Oid[]? enhancedKeyUsages,
        bool includeSubjectAlternativeName,
        bool includeAspNetHttpsExtension,
        bool includeBasicConstraints,
        bool includeKeyUsage,
        X509KeyUsageFlags keyUsage,
        bool keyUsageCritical,
        bool enhancedKeyUsageCritical,
        bool subjectAlternativeNameCritical,
        Action<SubjectAlternativeNameBuilder>? configureSubjectAlternativeNames)
    {
        if (includeBasicConstraints || includeAspNetHttpsExtension)
        {
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));
        }

        if (includeKeyUsage)
        {
            request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, keyUsageCritical));
        }

        if (enhancedKeyUsages is { Length: > 0 })
        {
            request.CertificateExtensions.Add(CreateEnhancedKeyUsageExtension(enhancedKeyUsages, enhancedKeyUsageCritical));
        }

        if (includeSubjectAlternativeName)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            configureSubjectAlternativeNames ??= ConfigureLocalhostSubjectAlternativeNames;
            configureSubjectAlternativeNames(sanBuilder);
            request.CertificateExtensions.Add(sanBuilder.Build(subjectAlternativeNameCritical));
        }

        if (includeAspNetHttpsExtension)
        {
            request.CertificateExtensions.Add(new X509Extension(
                new AsnEncodedData(
                    new Oid(AspNetHttpsOid, AspNetHttpsOidFriendlyName),
                    [(byte)AspNetHttpsCertificateVersion]),
                critical: false));
        }

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddYears(5);
        using var certificate = request.CreateSelfSigned(notBefore, notAfter);

        return new X509Certificate2(certificate.Export(X509ContentType.Pfx), string.Empty, X509KeyStorageFlags.Exportable);
    }

    private static X509EnhancedKeyUsageExtension CreateEnhancedKeyUsageExtension(Oid[] enhancedKeyUsages, bool critical)
    {
        var oidCollection = new OidCollection();
        foreach (var oid in enhancedKeyUsages)
        {
            oidCollection.Add(oid);
        }

        return new X509EnhancedKeyUsageExtension(oidCollection, critical);
    }
}
