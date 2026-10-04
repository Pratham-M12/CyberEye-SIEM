import OpenAI from "openai";

const client = new OpenAI({
    apiKey: process.env.GROQ_API_KEY,
    baseURL: "https://api.groq.com/openai/v1"
});

const MODEL =
    process.env.GROQ_MODEL ??
    "openai/gpt-oss-20b";

export async function investigateWithGroq(prompt){
    try {
        const response = await client.chat.completions.create({
            model: MODEL,
            temperature: 0.2,
            response_format:{
                type:"json_object"
            },
            messages:[
                {
                    role:"system",
                    content: "You are an expert SOC Analyst."
                },
                {
                    role:"user",
                    content:prompt
                }
            ]
        }, { timeout: 30000 });

        return JSON.parse(
            response.choices[0].message.content
        );
    } catch (err) {
        throw new Error(`Groq investigation failed: ${err.message}`);
    }
}