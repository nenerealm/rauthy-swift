import Foundation

/// Internal helper for building `multipart/form-data` request bodies.
///
/// Foundation has no built-in multipart builder, so we hand-roll it.
/// This implementation supports a single file part — which is all the
/// Rauthy avatar-upload endpoint needs.
internal enum MultipartFormData {
    /// Build a `multipart/form-data` body with a single file part.
    ///
    /// The returned `Data` becomes `URLRequest.httpBody`. The caller is
    /// responsible for setting the matching
    /// `Content-Type: multipart/form-data; boundary=<boundary>` header.
    ///
    /// - Parameters:
    ///   - boundary: Boundary string (caller's responsibility to make it unique).
    ///   - fieldName: Form field name. Rauthy ignores it, but the spec requires it.
    ///   - filename: Filename to advertise. Used by some servers for content-sniffing.
    ///   - mimeType: Image MIME type (e.g. "image/jpeg", "image/png").
    ///   - data: Raw file bytes.
    static func build(
        boundary: String,
        fieldName: String,
        filename: String,
        mimeType: String,
        data: Data
    ) -> Data {
        var body = Data()
        let crlf = "\r\n"
        body.append(Data("--\(boundary)\(crlf)".utf8))
        body.append(Data(
            "Content-Disposition: form-data; name=\"\(fieldName)\"; filename=\"\(filename)\"\(crlf)"
                .utf8))
        body.append(Data("Content-Type: \(mimeType)\(crlf)\(crlf)".utf8))
        body.append(data)
        body.append(Data("\(crlf)--\(boundary)--\(crlf)".utf8))
        return body
    }
}
