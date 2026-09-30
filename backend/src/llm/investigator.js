// backend/src/llm/investigator.js

import { buildInvestigationPrompt, PROMPT_VERSION } from "./promptBuilder.js";
import { runInvestigation } from "./provider.js";

export async function investigateAlert(alert) {
    const prompt = buildInvestigationPrompt(alert);
    const report = await runInvestigation(prompt);
    validateReport(report);
    return {
        report,
        metadata:{
            provider:
                process.env.LLM_PROVIDER,
            model:
                process.env.GROQ_MODEL,
            promptVersion:
                PROMPT_VERSION,
            generatedAt:
                new Date().toISOString()
        }
    };
}

function validateReport(report){
    const required = [
        "executiveSummary",
        "threatLevel",
        "confidence",
        "attackChain",
        "iocs",
        "mitre",
        "falsePositives",
        "containment",
        "recovery"
    ];
    for(const key of required){
        if(!(key in report)){
            throw new Error(
                `LLM response missing field: ${key}`
            );
        }
    }
}