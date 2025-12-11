// js/supabaseClient.js (수정 완료 버전)
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const supabaseUrl = "https://byxwhsnbekwazucaaysj.supabase.co";
const supabaseKey =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJ5eHdoc25iZWt3YXp1Y2FheXNqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjQzNTExNTMsImV4cCI6MjA3OTkyNzE1M30.1Q2jlYWjF9yTeqpc_g3Dr-Kp8za9VP93MFsLmnGs9FM";

export const supabase = createClient(supabaseUrl, supabaseKey);
