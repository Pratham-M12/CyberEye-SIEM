// backend/src/llm/provider.js

import { investigateWithGroq } from "./groq.js";

const provider =
    process.env.LLM_PROVIDER?.toLowerCase() ??
    "groq";

export async function runInvestigation(prompt){

    switch(provider){

        case "groq":
            return investigateWithGroq(prompt);

        default:
            throw new Error(
                `Unsupported LLM provider: ${provider}`
            );
    }

}