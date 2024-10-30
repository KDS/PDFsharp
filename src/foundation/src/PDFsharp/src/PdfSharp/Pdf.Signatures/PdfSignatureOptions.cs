﻿﻿using PdfSharp.Drawing;
using System.Security.Cryptography.X509Certificates;

namespace PdfSharp.Pdf.Signatures
{
    public class PdfSignatureOptions
    {
        /// <summary>
        /// Certificate to sign the document with
        /// </summary>
        public X509Certificate2? Certificate { get; set; }

        /// <summary>
        /// Uri of a timestamp authority used to get a timestamp from a trusted authority
        /// </summary>
        public Uri? TimestampAuthorityUri { get; set; }

        /// <summary>
        /// The name of the signer.<br></br>
        /// If not set, defaults to the Subject of the provided Certificate
        /// </summary>
        public string? Signer { get; set; }

        /// <summary>
        /// Contact info for the signer
        /// </summary>
        public string? ContactInfo { get; set; }

        /// <summary>
        /// The location where the signing took place
        /// </summary>
        public string? Location { get; set; }

        /// <summary>
        /// The reason for signing
        /// </summary>
        public string? Reason { get; set; }

        /// <summary>
        /// Intended to create a DocMPD signature entry.<br></br>
        /// Not implemented yet
        /// </summary>
        public bool Certify { get; set; }

        /// <summary>
        /// Rectangle of the Signature-Field's Annotation.<br></br>
        /// Specify an empty rectangle to create an invisible signature.<br></br>
        /// Note: <br></br>The rectangle's reference-point is the bottom left corner.<br></br>
        /// The recangle's location on the page is measured from the bottom-left corner.
        /// </summary>
        public XRect Rectangle { get; set; } = XRect.Empty;

        /// <summary>
        /// Page index for the signature's annotation, zero-based. Only needed for visible signatures.
        /// </summary>
        public int PageIndex { get; set; } = 0;

        /// <summary>
        /// The name of the Signature-Field.<br></br>
        /// If a field with that name already exist in the document, it will be used, otherwise it will be created.<br></br>
        /// Currently, only root-fields are supported (that is, the existing field is not allowed to be a child of another field)
        /// </summary>
        public string FieldName { get; set; } = "Signature1";

        /// <summary>
        /// An image to render as the Field's Annotation
        /// </summary>
        public XImage? Image { get; set; }

        /// <summary>
        /// A custom appearance renderer for the signature
        /// </summary>
        public ISignatureRenderer? Renderer { get; set; }
    }
}
