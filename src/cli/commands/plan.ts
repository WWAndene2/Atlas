// atlas plan agents --mode adaptive|high|medium|low [--agents <n>] [--bounds <b1,b2>]
import { agentPlan, MODES, type Mode } from "../../orchestrator/agent-plan.js";
import { CliError, type Output } from "../output.js";

export function runPlanAgents(
  args: string[],
  graph: string,
  options: { mode?: string; agents?: string; bounds?: string },
): Output {
  const [what, ...extra] = args;
  if (
    what !== "agents" ||
    extra.length > 0 ||
    options.mode === undefined ||
    !(MODES as readonly string[]).includes(options.mode)
  ) {
    throw new CliError("usage", `usage: atlas plan agents --mode ${MODES.join("|")} [--agents <n>] [--bounds <b1,b2>]`);
  }
  const total = Number(options.agents ?? "4");
  if (!Number.isInteger(total) || total < 1) throw new CliError("usage", "--agents takes a number of subagents");
  let plan;
  try {
    plan = agentPlan(options.mode as Mode, total, graph, options.bounds);
  } catch (error) {
    throw new CliError("usage", (error as Error).message);
  }
  const lines = [
    `Mode ${plan.mode}: ${plan.tiers.reduce((n, t) => n + t.agents.length, 0)} subagents`,
    ...plan.tiers.map((t) => `- ${t.agents.length} x ${t.model} (${t.agents.join(", ")}): ${t.takes}\n    ${t.claim}`),
    `Each subagent's loop: ${plan.loop}`,
  ];
  return { data: plan, text: lines.join("\n") };
}
