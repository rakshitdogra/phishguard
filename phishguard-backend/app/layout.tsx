import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = { title: "PhishGuard — Email Analyzer", description: "Analyze suspicious email indicators with explainable checks and optional threat intelligence integrations." };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body>{children}</body></html>; }
