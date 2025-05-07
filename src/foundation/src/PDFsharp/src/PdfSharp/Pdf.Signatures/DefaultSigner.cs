// PDFsharp - A .NET library for processing PDF
// See the LICENSE file in the solution root for more information.

#if WPF
using System.IO;
#endif
#if NET6_0_OR_GREATER
using System.Formats.Asn1;
using System.Net.Http.Headers;
#if WPF
    using System.Net.Http;
#endif
#else
using Org.BouncyCastle.Asn1;
#endif
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace PdfSharp.Pdf.Signatures
{
    public class DefaultSigner : ISigner
    {
        private static readonly Oid SignatureTimeStampOin = new Oid("1.2.840.113549.1.9.16.2.14");
        private static readonly string TimestampQueryContentType = "application/timestamp-query";
        private static readonly string TimestampReplyContentType = "application/timestamp-reply";

        private readonly PdfSignatureOptions options;

        public DefaultSigner(PdfSignatureOptions signatureOptions)
        {
            if (signatureOptions?.Certificate is null)
                throw new ArgumentException("Missing certificate in signature options");

            options = signatureOptions;
        }

        public byte[] GetSignedCms(Stream documentStream, PdfDocument document)
        {
            var range = new byte[documentStream.Length];
            documentStream.Position = 0;
            documentStream.Read(range, 0, range.Length);

            return GetSignedCms(range, document);
        }

        public byte[] GetSignedCms(byte[] range, PdfDocument document)
        {
            var cert = options.Certificate!;

            // Sign the byte range
            var contentInfo = new ContentInfo(range);
            var signedCms = new SignedCms(contentInfo, true);
            var signer = new CmsSigner(cert)
            {
                DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"),
                IncludeOption = X509IncludeOption.WholeChain,
            };

            foreach (var attr in signer.SignedAttributes)
            {
                signer.SignedAttributes.Remove(attr);
            }

            signer.SignedAttributes.Add(new Pkcs9SigningTime());

            var signingCert = SigningCertV2(cert.RawData);
            if (signingCert != null)
            {
                signer.SignedAttributes.Add(signingCert);
            }

            signedCms.ComputeSignature(signer, true);

            if (options.TimestampAuthorityUri is not null)
            {
                Task.Run(() => AddTimestampFromTSAAsync(signedCms)).Wait();
            }

            var bytes = signedCms.Encode();

            return bytes;
        }

        public string? GetName()
        {
            return options.Certificate?.GetNameInfo(X509NameType.SimpleName, false);
        }

        private async Task AddTimestampFromTSAAsync(SignedCms signedCms)
        {
            // Generate our nonce to identify the pair request-response
            byte[] nonce = new byte[8];
#if NET6_0_OR_GREATER
            nonce = RandomNumberGenerator.GetBytes(8);
#else
            using var cryptoProvider = new RNGCryptoServiceProvider();
            cryptoProvider.GetBytes(nonce = new Byte[8]);
#endif
#if NET6_0_OR_GREATER
            // Get our signing information and create the RFC3161 request
            SignerInfo newSignerInfo = signedCms.SignerInfos[0];
            // Now we generate our request for us to send to our RFC3161 signing authority.
            var request = Rfc3161TimestampRequest.CreateFromSignerInfo(
                newSignerInfo,
                HashAlgorithmName.SHA256,
                requestSignerCertificates: true, // ask TSA to embed its signing certificate in the timestamp token
                nonce: nonce);

            var client = new HttpClient();
            var content = new ReadOnlyMemoryContent(request.Encode());
            content.Headers.ContentType = new MediaTypeHeaderValue(TimestampQueryContentType);
            var httpResponse = await client.PostAsync(options.TimestampAuthorityUri, content).ConfigureAwait(false);

            // Process our response
            if (!httpResponse.IsSuccessStatusCode)
            {
                throw new CryptographicException(
                    $"There was a error from the timestamp authority. It responded with {httpResponse.StatusCode} {(int)httpResponse.StatusCode}: {httpResponse.Content}");
            }
            if (httpResponse.Content.Headers.ContentType?.MediaType != TimestampReplyContentType)
            {
                throw new CryptographicException("The reply from the time stamp server was in a invalid format.");
            }
            var data = await httpResponse.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            var timestampToken = request.ProcessResponse(data, out _);

            // The RFC3161 sign certificate is separate to the contents that was signed, we need to add it to the unsigned attributes.
            newSignerInfo.AddUnsignedAttribute(new AsnEncodedData(SignatureTimeStampOin, timestampToken.AsSignedCms().Encode()));
#endif
        }

        private AsnEncodedData? SigningCertV2(byte[] certRawData)
        {
            byte[] certHash;
            using (var sha256 = SHA256.Create())
            {
                certHash = sha256.ComputeHash(certRawData);
            }

#if NET6_0_OR_GREATER
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence(); // SigningCertificateV2 SEQUENCE
            writer.PushSequence(); // certs SEQUENCE

            writer.PushSequence(); // ESSCertIDv2

            // Hash algorithm identifier (SHA-256)
            writer.PushSequence();
            writer.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); // SHA-256
            writer.PopSequence();

            // certHash (OCTET STRING)
            writer.WriteOctetString(certHash);

            writer.PopSequence(); // End of ESSCertIDv2

            writer.PopSequence(); // End of certs
            writer.PopSequence(); // End of SigningCertificateV2

            var essAttr = new AsnEncodedData(
                new Oid("1.2.840.113549.1.9.16.2.47"), // SigningCertificateV2
                writer.Encode());

            return essAttr;
#else
            // SHA-256 OID
            DerObjectIdentifier sha256Oid = new DerObjectIdentifier("2.16.840.1.101.3.4.2.1");

            // Build AlgorithmIdentifier sequence (hash algorithm)
            Asn1EncodableVector hashAlgVector = new Asn1EncodableVector();
            hashAlgVector.Add(sha256Oid);
            hashAlgVector.Add(DerNull.Instance);
            DerSequence hashAlgSeq = new DerSequence(hashAlgVector);

            // Build ESSCertIDv2 sequence
            Asn1EncodableVector essCertVector = new Asn1EncodableVector();
            essCertVector.Add(hashAlgSeq);
            essCertVector.Add(new DerOctetString(certHash));
            DerSequence essCertSeq = new DerSequence(essCertVector);

            // certs SEQUENCE (of ESSCertIDv2)
            Asn1EncodableVector certsVector = new Asn1EncodableVector();
            certsVector.Add(essCertSeq);
            DerSequence certsSeq = new DerSequence(certsVector);

            // SigningCertificateV2 SEQUENCE
            Asn1EncodableVector signingCertV2Vector = new Asn1EncodableVector();
            signingCertV2Vector.Add(certsSeq);
            DerSequence signingCertV2 = new DerSequence(signingCertV2Vector);

            // Wrap in AsnEncodedData (to match return type)
            var essAttr = new AsnEncodedData(
                new Oid("1.2.840.113549.1.9.16.2.47"),
                signingCertV2.GetDerEncoded());

            return essAttr;
#endif
        }
    }
}
