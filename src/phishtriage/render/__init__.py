"""Renderers: each one prints a report.Report in one format (week 4, steps 10-12).

    terminal.py   the coloured report in the terminal (step 10)
    markdown.py   Markdown, for tickets, wikis and chat (step 11)
    html.py       one HTML file for a browser, with a strict Content-Security-Policy
    json_report.py  JSON for scripts, with report.schema.json describing it (step 12)
    safety.py     find_unsafe(): reads a finished Markdown, HTML or JSON report back and
                  reports anything that could run, load, link or hide (steps 11-12)
    common.py     wording shared by all of them
    templates/    the Jinja2 templates for Markdown and HTML

A renderer only formats. Every decision (the score, what counts, what is redacted or
defanged) was already made when the Report was built, so all formats agree.
"""
