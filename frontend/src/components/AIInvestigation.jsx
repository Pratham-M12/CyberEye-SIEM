export default function AIInvestigation({ report }) {

    if (!report) {
        return (
            <div className="rounded-md border border-hairline bg-void p-4">
                <p className="text-sm text-ink-muted">
                    No investigation generated yet.
                </p>
            </div>
        );
    }
    
    return (
        <div className="space-y-5">
            <section>
                <h3 className="font-mono text-xs uppercase text-ink-muted">
                    Executive Summary
                </h3>
                <p className="mt-2 text-sm">
                    {report.executiveSummary}
                </p>
            </section>
            <section>
                <h3 className="font-mono text-xs uppercase text-ink-muted">
                    Threat Level
                </h3>
                <div className="mt-2">
                    <span className="rounded bg-red-600 px-2 py-1 text-xs">
                        {report.threatLevel}
                    </span>
                </div>
            </section>
            <section>
                <h3 className="font-mono text-xs uppercase text-ink-muted">
                    Confidence
                </h3>
                <p className="mt-2">
                    {report.confidence}%
                </p>
            </section>
            <section>
                <h3 className="font-mono text-xs uppercase text-ink-muted">
                    Attack Chain
                </h3>
                <ul className="mt-2 list-disc pl-6">
                    {report.attackChain.map(step => (
                        <li key={step}>{step}</li>
                    ))}
                </ul>
            </section>
            <section>
                <h3 className="font-mono text-xs uppercase text-ink-muted">
                    Indicators of Compromise
                </h3>
                <ul className="mt-2 list-disc pl-6">
                    {report.iocs.map(ioc => (
                        <li key={ioc}>{ioc}</li>
                    ))}
                </ul>
            </section>
        </div>
    );
}