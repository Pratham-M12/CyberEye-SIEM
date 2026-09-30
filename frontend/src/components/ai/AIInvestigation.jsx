import ThreatScoreCard from "./ThreatScoreCard";
import ExecutiveSummaryCard from "./ExecutiveSummaryCard";

export default function AIInvestigation({
  investigation,
}) {
  return (
    <div className="space-y-5">
      <ThreatScoreCard score={92} />
      <ExecutiveSummaryCard
        summary={investigation}
      />
    </div>
  );
}