"""A governed MCP server for organisational databases.

The hard part of connecting a language model to a company database is not the
connection. It is everything that has to refuse: queries outside a role's
remit, statements that are not reads, requests for columns nobody authorised,
and results large enough to be an exfiltration channel.

This package is organised around that refusal.
"""

__version__ = "0.1.0"
