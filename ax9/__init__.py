"""AX9 (Audit X9): automated audit of PCI audit-log coverage, freshness and retention.

Package map (read in this order to understand the tool):
    models.py     the data structures
    ingest.py     reading and validating the input files
    engine.py     the control rules and verdicts
    reporters.py  JSON / CSV / Markdown / terminal outputs
    ui.py         banner, colors, tables, animation
    cli.py        command-line options and the run sequence
"""

__version__ = "1.0.0"
