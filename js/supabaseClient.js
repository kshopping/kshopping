// supabaseClient.js
import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/esm/supabase.js";

// 🔹 프로젝트 URL & ANON KEY
const SUPABASE_URL = "https://byxwhsnbekwazucaaysj.supabase.co";
const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9....(생략)";

// 🔹 Supabase 클라이언트 생성
export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// 🔹 전역에서도 접근 가능
window.supabase = supabase;
