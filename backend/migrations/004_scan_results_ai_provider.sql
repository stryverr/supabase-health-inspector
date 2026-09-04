-- 004_scan_results_ai_provider.sql
-- Records which LLM produced ai_explanation.
--
-- The UI previously labelled every narration block "GEMINI DIAGNOSTIC ANALYSIS"
-- regardless of origin. With the provider layer that label can be wrong in two
-- directions at once: Gemini returning 401 while Ollama answers. Storing the
-- provider makes the label a fact rather than an assumption, including for
-- historical scans read back from the control plane.
--
-- NULL means narration was unavailable for that module.

ALTER TABLE public.scan_results ADD COLUMN IF NOT EXISTS ai_provider TEXT;
