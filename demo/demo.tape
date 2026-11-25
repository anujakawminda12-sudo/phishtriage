# PhishTriage demo: a short GIF for the README, made by VHS (https://github.com/charmbracelet/vhs).
#
# Run from the project folder, with the virtual environment set up:
#     vhs demo/demo.tape
# It writes demo/demo.gif. Only the safe, hand-built test emails in tests/fixtures are used:
# no --enrich (nothing is looked up) and no `phishtriage config`.

Output demo/demo.gif

Require phishtriage

Set Shell "bash"
Set FontSize 16
Set Width 1300
Set Height 760
Set Padding 24
Set TypingSpeed 35ms

# Not recorded: a plain prompt, and colour even when a report is piped into head
Hide
Type "source .venv/bin/activate && export PS1='$ ' FORCE_COLOR=1 COLUMNS=110 && clear"
Enter
Show

# 1. One email: the verdict and the reasons behind every point
Type "# Triage one email: verdict, score and the reason for every point"
Enter
Type "phishtriage analyze tests/fixtures/phish_paypal_spoof.eml | head -16"
Sleep 400ms
Enter
Sleep 7s

Hide
Type "clear"
Enter
Show

# 2. Exit codes a script or SOAR playbook can branch on
Type "# The exit code is the verdict: 2 malicious, 1 suspicious, 0 likely benign"
Enter
Type "phishtriage analyze tests/fixtures/phish_paypal_spoof.eml > /dev/null; echo $?"
Enter
Sleep 1500ms
Type "phishtriage analyze tests/fixtures/phish_open_redirect.eml > /dev/null; echo $?"
Enter
Sleep 1500ms
Type "phishtriage analyze tests/fixtures/legit_newsletter.eml > /dev/null; echo $?"
Enter
Sleep 4s

Hide
Type "clear"
Enter
Show

# 3. A whole folder, worst first
Type "# A morning queue of reported emails, worst first"
Enter
Type "phishtriage analyze tests/fixtures/"
Sleep 400ms
Enter
Sleep 8s
