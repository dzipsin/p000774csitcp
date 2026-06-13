"""Evaluation harness for the SOC triage system - standalone, not part of the app.

This package is never imported by the main application. It is used only during
the capstone evaluation campaign to fire attack scenarios against DVWA and measure
detection accuracy. It depends on DVWA running at a known URL with default credentials.

Entry point: python -m src.evaluation.run_evaluation
"""