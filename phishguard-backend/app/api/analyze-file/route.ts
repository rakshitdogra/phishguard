import { NextRequest, NextResponse } from "next/server";
import { simpleParser } from "mailparser";
import { analyzeEmail } from "@/lib/analyzer";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const MAX_FILE_BYTES = 1_000_000; // 1 MB: bound MIME parsing and memory use.

function headerText(parsed: Awaited<ReturnType<typeof simpleParser>>) {
  // Preserve original header lines for the existing heuristic header parser.
  return (parsed.headerLines || []).map((item) => item.line).join("\n");
}

export async function POST(request: NextRequest) {
  try {
    const length = Number(request.headers.get("content-length") || 0);
    if (length > MAX_FILE_BYTES + 100_000) {
      return NextResponse.json({ error: "Upload too large. Email files must be 1 MB or smaller." }, { status: 413 });
    }
    const form = await request.formData();
    const file = form.get("file");
    if (!(file instanceof File)) {
      return NextResponse.json({ error: "Choose an .eml or .txt email file first." }, { status: 400 });
    }
    if (file.size === 0) return NextResponse.json({ error: "The selected file is empty." }, { status: 400 });
    if (file.size > MAX_FILE_BYTES) return NextResponse.json({ error: "Email files must be 1 MB or smaller." }, { status: 413 });

    const fileName = file.name || "email.eml";
    const extension = fileName.toLowerCase().split(".").pop();
    if (extension !== "eml" && extension !== "txt") {
      return NextResponse.json({ error: "Unsupported file type. Upload a raw .eml email or a .txt file containing raw email headers and body. Outlook .msg files are not supported yet." }, { status: 415 });
    }

    // Parse as inert text/MIME only. No links are opened and no attachment is extracted to disk or executed.
    const raw = await file.text();
    const parsed = await simpleParser(raw, { skipHtmlToText: false, skipTextToHtml: true });
    const from = parsed.from?.value?.[0];
    const sender = from?.address || "";
    const displayName = from?.name || "";
    const subject = parsed.subject || "";
    const body = (parsed.text || "").slice(0, 50_000);
    const attachments = parsed.attachments.map((item) => item.filename || "unnamed-attachment").join(", ").slice(0, 10_000);
    const headers = headerText(parsed).slice(0, 50_000);

    if (!sender && !subject && !body && !headers) {
      return NextResponse.json({ error: "No readable email fields were found. Check that this is a raw .eml or .txt message." }, { status: 400 });
    }
    const report = await analyzeEmail({ sender, displayName, subject, body, attachments, headers, attachmentHashes: [] });
    return NextResponse.json({
      fileName,
      extracted: { sender, displayName, subject, body, attachments, headers },
      report,
      fileScan: { status: "parsed", attachmentContentsScanned: false, note: "Email headers, body, URLs and attachment filenames were analyzed. Attachment bytes were not saved to disk, scanned, uploaded, or executed." }
    }, { headers: { "Cache-Control": "no-store, max-age=0", "X-Content-Type-Options": "nosniff" } });
  } catch {
    return NextResponse.json({ error: "Could not parse this email file. Try a valid raw .eml or .txt file under 1 MB." }, { status: 400, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
  }
}
