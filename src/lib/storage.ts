// Storage layer — saves and retrieves investigations from Supabase
import { createClient } from "@supabase/supabase-js";
import type { AnalysisResult } from "./types";

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL as string;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string;

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

export interface InvestigationRecord {
  id: string;
  filename: string;
  uploaded_at: string;
  analyzed_at: string;
  status: string;
  sender: string;
  recipient: string;
  subject: string;
  threat_score: number;
  threat_level: string;
  summary: string;
  indicator_counts: {
    ips: number;
    domains: number;
    urls: number;
    attachments: number;
  };
  result_data: AnalysisResult;
  created_at: string;
}

export async function saveInvestigation(result: AnalysisResult): Promise<void> {
  const record = {
    id: result.investigationId,
    filename: result.filename,
    uploaded_at: result.uploadedAt,
    analyzed_at: result.analyzedAt,
    status: result.status,
    sender: result.email.fromAddress || "",
    recipient: result.email.to.join(", "),
    subject: result.email.subject,
    threat_score: result.risk.score,
    threat_level: result.risk.level,
    summary: result.aiAssessment.executiveSummary,
    indicator_counts: {
      ips: result.indicators.ips.length,
      domains: result.indicators.domains.length,
      urls: result.indicators.urls.length,
      attachments: result.indicators.attachments.length,
    },
    result_data: result,
  };

  const { error } = await supabase.from("investigations").insert(record);
  if (error) throw new Error(`Failed to save investigation: ${error.message}`);
}

export async function listInvestigations(): Promise<InvestigationRecord[]> {
  const { data, error } = await supabase
    .from("investigations")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) throw new Error(`Failed to list investigations: ${error.message}`);
  return (data || []) as InvestigationRecord[];
}

export async function getInvestigation(id: string): Promise<InvestigationRecord | null> {
  const { data, error } = await supabase
    .from("investigations")
    .select("*")
    .eq("id", id)
    .maybeSingle();

  if (error) throw new Error(`Failed to get investigation: ${error.message}`);
  return data as InvestigationRecord | null;
}

export async function deleteInvestigation(id: string): Promise<void> {
  const { error } = await supabase.from("investigations").delete().eq("id", id);
  if (error) throw new Error(`Failed to delete investigation: ${error.message}`);
}
