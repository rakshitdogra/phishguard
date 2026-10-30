import { NextRequest, NextResponse } from "next/server";
import { createHash } from "node:crypto";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const MAX_FILE_BYTES = 10 * 1024 * 1024;

export async function POST(request: NextRequest) {
  try {
    const form = await request.formData();
    const entry = form.get("file");
    if (!(entry instanceof File)) return NextResponse.json({ error: "No attachment file received." }, { status: 400 });
    if (!entry.size) return NextResponse.json({ error: "Attachment is empty." }, { status: 400 });
    if (entry.size > MAX_FILE_BYTES) return NextResponse.json({ error: "Attachments must be 10 MB or smaller." }, { status: 413 });

    const bytes = Buffer.from(await entry.arrayBuffer());
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (process.env.PHISHGUARD_OFFLINE_MODE === "true") {
      return NextResponse.json({ fileName: entry.name, sha256, status: "offline mode", scanned: false, note: "External reputation lookups are disabled by PHISHGUARD_OFFLINE_MODE." }, { headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
    }
    if (!apiKey) {
      return NextResponse.json({
        fileName: entry.name, sha256, status: "inconclusive",
        note: "File bytes were received and SHA-256 was calculated, but no malware reputation provider is configured. Set VIRUSTOTAL_API_KEY on the backend to check file reputation.",
        scanned: false
      }, { headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
    }

    const headers = { "x-apikey": apiKey };
    const lookup = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, { headers, cache: "no-store", signal: AbortSignal.timeout(10000) });
    if (lookup.ok) {
      const data = await lookup.json();
      const stats = data?.data?.attributes?.last_analysis_stats || {};
      const malicious = Number(stats.malicious || 0), suspicious = Number(stats.suspicious || 0);
      return NextResponse.json({
        fileName: entry.name, sha256,
        status: malicious > 0 ? "malicious" : suspicious > 0 ? "suspicious" : "no known threat detected",
        stats, scanned: true, source: "VirusTotal existing file reputation",
        note: "Based on the provider's latest available analysis; a clean result is not a guarantee of safety."
      }, { headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
    }

    if (lookup.status !== 404) {
      const detail = lookup.status === 401 || lookup.status === 403
        ? "VirusTotal rejected the API key or permission. Check VIRUSTOTAL_API_KEY and account access."
        : `VirusTotal hash lookup failed (${lookup.status}).`;
      return NextResponse.json({ error: detail, fileName: entry.name, sha256 }, { status: 502 });
    }

    // Unknown hashes are submitted only when the owner explicitly enables uploads.
    // VirusTotal submissions share files with the provider and potentially its partners.
    if (process.env.PHISHGUARD_ALLOW_VT_FILE_UPLOAD !== "true") {
      return NextResponse.json({
        fileName: entry.name, sha256, status: "unknown file",
        scanned: false,
        note: "No existing VirusTotal report was found. To submit unknown attachment bytes to VirusTotal for analysis, set PHISHGUARD_ALLOW_VT_FILE_UPLOAD=true on the backend after reviewing the privacy implications."
      }, { headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
    }

    const uploadForm = new FormData();
    uploadForm.append("file", new Blob([bytes], { type: entry.type || "application/octet-stream" }), entry.name || "attachment.bin");
    const upload = await fetch("https://www.virustotal.com/api/v3/files", { method: "POST", headers, body: uploadForm, cache: "no-store", signal: AbortSignal.timeout(10000) });
    const uploadData = await upload.json().catch(() => ({}));
    if (!upload.ok) return NextResponse.json({ error: `VirusTotal upload failed (${upload.status}).`, detail: uploadData?.error?.message || "" }, { status: 502 });
    return NextResponse.json({
      fileName: entry.name, sha256, status: "submitted for analysis", scanned: true,
      analysisId: uploadData?.data?.id || null,
      note: "File bytes were submitted to VirusTotal. Results may take time to become available; submission may share the file with VirusTotal and its partners."
    }, { headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
  } catch {
    return NextResponse.json({ error: "Could not process the attachment safely." }, { status: 400, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
  }
}
