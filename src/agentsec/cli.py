"""AgentSec Range command line.

    agentsec taxonomy                     list the OWASP ASI01-10 categories
    agentsec attacks                      list attacks with their ASI id and mitigations
    agentsec defenses                     list defense presets and the guards they enable
    agentsec run --attack ... --defense   run one scenario and print its incident trace
    agentsec experiment                   sweep all presets, print the security-utility table
    agentsec pareto                       print the security-utility Pareto frontier
    agentsec verify-gate                  acceptance gate: every mitigation vs its attack
"""

from __future__ import annotations

import typer

from agentsec import __version__
from agentsec.agent import PROFILES, run_scenario
from agentsec.attacks import CATALOG as ATTACKS
from agentsec.attacks import get_attack
from agentsec.defenses import PRESETS, get_preset
from agentsec.experiment import pareto_frontier, summarise_all, verify_gate
from agentsec.tasks import get_task
from agentsec.taxonomy import CATALOG as ASI_CATALOG

app = typer.Typer(add_completion=False, help="Long-horizon agent attack/defense range.")


def _pct(x: float) -> str:
    return f"{x * 100:5.1f}%"


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(f"agentsec {__version__}")


@app.command()
def taxonomy() -> None:
    """List the OWASP ASI01-10 threat categories."""
    for info in ASI_CATALOG.values():
        typer.echo(f"{info.id.value}  {info.title}")
        typer.echo(f"        {info.summary}")


@app.command()
def attacks() -> None:
    """List the attack catalog with ASI id, task, and mapped mitigations."""
    typer.echo(f"{'attack':22} {'ASI':6} {'task':16} mitigations")
    for a in ATTACKS.values():
        typer.echo(f"{a.id:22} {a.asi.value:6} {a.task_id:16} {', '.join(a.primary_mitigations)}")


@app.command()
def defenses() -> None:
    """List defense presets and the guards each one enables."""
    for name, factory in PRESETS.items():
        cfg = factory()
        guards = cfg.enabled_guards()
        extra = " +strict-taint" if cfg.taint_strict else ""
        typer.echo(f"{name:18} {', '.join(guards) or '(none)'}{extra}")


@app.command()
def run(
    attack: str = typer.Option("goal-hijack", help="Attack id (or 'none' for a benign run)."),
    defense: str = typer.Option("no_defense", help="Defense preset."),
    model: str = typer.Option("weak-model", help="Model profile."),
    seed: int = typer.Option(0, help="Random seed."),
) -> None:
    """Run a single scenario and print the outcome plus the incident trace."""
    atk = None if attack == "none" else get_attack(attack)
    task = get_task(atk.task_id if atk else "pay-invoice")
    cfg = get_preset(defense)
    prof = PROFILES[model]
    o = run_scenario(task, atk, cfg, prof, seed=seed)

    typer.echo(f"Task:      {o.task_id}")
    typer.echo(f"Attack:    {o.attack_id or 'none'}")
    typer.echo(f"Defense:   {o.defense}    Model: {o.model}    Seed: {seed}")
    typer.echo("-" * 60)
    typer.echo(f"attack_success:      {o.attack_success}")
    typer.echo(f"benign_success:      {o.benign_success}")
    typer.echo(f"time_to_compromise:  {o.time_to_compromise}")
    typer.echo(f"privilege_reached:   {o.privilege_reached}")
    typer.echo(f"exfiltration:        {o.exfiltration}")
    typer.echo(f"memory_persistence:  {o.memory_persistence}")
    typer.echo(f"unauthorized_effects:{o.unauthorized_effects}")
    typer.echo(f"false_blocks:        {o.false_blocks}")
    typer.echo(f"approval_burden:     {o.approval_burden}")
    typer.echo(f"latency (guards):    {o.latency}")
    if o.incidents:
        typer.echo("-" * 60)
        typer.echo("Incident trace:")
        for inc in o.incidents:
            tag = inc.guard or inc.kind
            typer.echo(f"  step {inc.step:>3}  [{tag}] {inc.detail}")


@app.command()
def experiment(
    seeds: int = typer.Option(5, help="Seeds per (attack, model) cell."),
    models: str = typer.Option("", help="Comma-separated model names (default: all)."),
) -> None:
    """Sweep every defense preset and print the security-utility table."""
    mlist = [m for m in models.split(",") if m] or None
    summaries = summarise_all(models=mlist, seeds=seeds)
    header = (f"{'defense':18} {'attack_succ':>12} {'benign_succ':>12} {'false_block':>12} "
              f"{'approvals':>10} {'latency':>8}")
    typer.echo(header)
    typer.echo("-" * len(header))
    for s in summaries:
        typer.echo(
            f"{s.defense:18} {_pct(s.attack_success.point):>12} "
            f"{_pct(s.benign_success.point):>12} {_pct(s.false_block.point):>12} "
            f"{s.approval_burden:>10.2f} {s.latency:>8.1f}")


@app.command()
def pareto(
    seeds: int = typer.Option(5, help="Seeds per cell."),
) -> None:
    """Print the security-utility Pareto frontier with confidence intervals."""
    summaries = summarise_all(seeds=seeds)
    frontier = {s.defense for s in pareto_frontier(summaries)}
    typer.echo(f"{'defense':18} {'security':>20} {'utility':>20}  frontier")
    typer.echo("-" * 70)
    for s in summaries:
        sec = f"{s.security:.2f} [{1 - s.attack_success.high:.2f},{1 - s.attack_success.low:.2f}]"
        ut = f"{s.utility:.2f} [{s.benign_success.low:.2f},{s.benign_success.high:.2f}]"
        mark = "  <== on frontier" if s.defense in frontier else ""
        typer.echo(f"{s.defense:18} {sec:>20} {ut:>20}{mark}")


@app.command()
def plot(
    out: str = typer.Option("docs/pareto.png", help="Output image path."),
    seeds: int = typer.Option(5, help="Seeds per cell."),
    live: bool = typer.Option(False, help="Use the live parsing agent instead of simulated."),
) -> None:
    """Render the security-utility Pareto frontier to an image (needs the plot extra)."""
    from agentsec.plotting import pareto_plot
    if live:
        from agentsec.experiment import live_summarise_all
        summaries = live_summarise_all()
        subtitle = "live parsing agent, one deterministic pass per cell"
    else:
        summaries = summarise_all(seeds=seeds)
        subtitle = f"simulated agents, {seeds} seeds/cell, Wilson 95% intervals"
    path = pareto_plot(summaries, out, subtitle=subtitle)
    typer.echo(f"wrote {path}")


@app.command(name="verify-gate")
def verify_gate_cmd(
    seeds: int = typer.Option(8, help="Seeds per attack."),
) -> None:
    """Acceptance gate: every attack must succeed undefended, be stopped by its mapped
    mitigation, and be stopped by the combined stack."""
    results = verify_gate(seeds=seeds)
    typer.echo(f"{'attack':22} {'ASI':6} {'mitigation':16} {'baseline':>9} "
               f"{'mapped':>7} {'combined':>9}  verdict")
    typer.echo("-" * 82)
    all_pass = True
    for r in results:
        all_pass = all_pass and r.passed
        typer.echo(f"{r.attack_id:22} {r.asi:6} {r.mitigation:16} "
                   f"{r.baseline_success!s:>9} {r.mitigated_blocked!s:>7} "
                   f"{r.combined_blocked!s:>9}  {'PASS' if r.passed else 'FAIL'}")
    typer.echo("-" * 82)
    typer.echo("GATE: " + ("PASS - every mitigation maps to a reproducible attack test"
                           if all_pass else "FAIL"))
    raise typer.Exit(code=0 if all_pass else 1)


@app.command()
def demo(seeds: int = typer.Option(20, help="Seeds per cell.")) -> None:
    """One-screen tour: the headline classifier-vs-deterministic contrast."""
    typer.echo("AgentSec Range: why classifier-only defense is not enough.")
    typer.echo("(attack-success rate over a susceptible model, higher = worse)\n")
    prof = PROFILES["weak-model"]

    def rate(a, preset):
        task = get_task(a.task_id)
        hits = sum(1 for s in range(seeds)
                   if run_scenario(task, a, get_preset(preset), prof, seed=s).attack_success)
        return hits / seeds

    typer.echo(f"{'attack':22} {'classifier_only':>16} {'deterministic':>14}")
    for attack_id in ("privilege-abuse", "delayed-memory", "forged-delegation",
                      "covert-exfiltration"):
        a = get_attack(attack_id)
        typer.echo(f"{a.asi.value} {a.id:18} {_pct(rate(a, 'classifier_only')):>16} "
                   f"{_pct(rate(a, 'deterministic')):>14}")
    typer.echo("\nThe classifier cannot see authorization violations or poison that was "
               "ingested\nsessions earlier. Deterministic controls stop both.")
    typer.echo("Run 'agentsec experiment' for the full table, 'agentsec verify-gate' for the "
               "acceptance gate.")


@app.command(name="run-live")
def run_live_cmd(
    attack: str = typer.Option("goal-hijack", help="Attack id (or 'none' for a benign run)."),
    defense: str = typer.Option("no_defense", help="Defense preset."),
    backend: str = typer.Option("parsing", help="parsing | parsing-cautious | hosted[:model] "
                                                "| ollama[:model]."),
    seed: int = typer.Option(0, help="Random seed."),
) -> None:
    """Run one scenario with a live agent that reads content and derives its own tool calls."""
    from agentsec.live import get_backend, run_live
    atk = None if attack == "none" else get_attack(attack)
    task = get_task(atk.task_id if atk else "pay-invoice")
    be = get_backend(backend)
    o = run_live(task, atk, get_preset(defense), be, seed=seed)
    typer.echo(f"Task:      {o.task_id}")
    typer.echo(f"Attack:    {o.attack_id or 'none'}")
    typer.echo(f"Defense:   {o.defense}    Agent: {o.model}    Seed: {seed}")
    typer.echo("-" * 60)
    typer.echo(f"attack_success:      {o.attack_success}")
    typer.echo(f"benign_success:      {o.benign_success}")
    typer.echo(f"exfiltration:        {o.exfiltration}")
    typer.echo(f"unauthorized_effects:{o.unauthorized_effects}")
    typer.echo(f"false_blocks:        {o.false_blocks}")
    if o.incidents:
        typer.echo("-" * 60)
        typer.echo("Incident trace:")
        for inc in o.incidents:
            typer.echo(f"  step {inc.step:>3}  [{inc.guard or inc.kind}] {inc.detail}")


@app.command(name="live-experiment")
def live_experiment_cmd(
    backend: str = typer.Option("parsing", help="Live backend: parsing | hosted[:model] | "
                                                "ollama[:model]."),
) -> None:
    """Security-utility table and Pareto frontier computed with a live agent that reads
    content, the same study as `experiment` but driven by real tool-call decisions."""
    from agentsec.experiment import live_summarise_all, pareto_frontier
    from agentsec.live import get_backend
    be = get_backend(backend)
    summaries = live_summarise_all(be)
    frontier = {s.defense for s in pareto_frontier(summaries)}
    typer.echo(f"Live agent: {be.name}   (rate denominator = attacks it is vulnerable to "
               f"undefended)\n")
    header = (f"{'defense':18} {'attack_succ':>12} {'benign_succ':>12} {'false_block':>12} "
              f"{'approvals':>10} {'latency':>8}  frontier")
    typer.echo(header)
    typer.echo("-" * len(header))
    for s in summaries:
        mark = "  <==" if s.defense in frontier else ""
        typer.echo(
            f"{s.defense:18} {_pct(s.attack_success.point):>12} "
            f"{_pct(s.benign_success.point):>12} {_pct(s.false_block.point):>12} "
            f"{s.approval_burden:>10.2f} {s.latency:>8.1f}{mark}")


@app.command(name="live-demo")
def live_demo() -> None:
    """A real content-reading agent, hijacked by what it reads, then stopped by the stack."""
    from agentsec.live import ParsingAgent, run_live
    typer.echo("Live ParsingAgent: it reads emails, docs, memory and tool manifests as text\n"
               "and derives its own tool calls. No model or API key required.\n")
    naive, cautious = ParsingAgent(), ParsingAgent(follow_content=False)
    typer.echo(f"{'attack':22} {'no_defense':>11} {'combined_mon':>13} {'cautious_agent':>15}")
    for aid in ("goal-hijack", "stored-injection", "delayed-memory", "malicious-manifest",
                "covert-exfiltration", "reward-hacking"):
        a = get_attack(aid)
        task = get_task(a.task_id)
        nd = run_live(task, a, get_preset("no_defense"), naive).attack_success
        cm = run_live(task, a, get_preset("combined_monitor"), naive).attack_success
        ca = run_live(task, a, get_preset("no_defense"), cautious).attack_success
        typer.echo(f"{a.asi.value} {a.id:18} {nd!s:>11} {cm!s:>13} {ca!s:>15}")
    typer.echo("\nThe agent gets hijacked purely by reading attacker-controlled content, the\n"
               "combined control plane stops every case, and a cautious agent that ignores\n"
               "instructions found inside data is never hijacked in the first place.")
    typer.echo("\nSwap in a real LLM with no local model:  "
               "agentsec run-live --backend hosted:gpt-4o-mini\n"
               "(set AGENTSEC_LLM_BASE, AGENTSEC_LLM_KEY, AGENTSEC_LLM_MODEL first).")


def _main() -> None:
    app()


if __name__ == "__main__":
    _main()
