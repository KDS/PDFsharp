// PDFsharp - A .NET library for processing PDF
// See the LICENSE file in the solution root for more information.

#if WPF
using System.IO;
#endif

namespace PdfSharp.Pdf.Signatures
{
    public interface ISigner
    {
        byte[] GetSignedCms(Stream documentStream, PdfDocument document);
        byte[] GetSignedCms(byte[] range, PdfDocument document);

        string? GetName();
        int GetSize(PdfDocument document);
    }
}
