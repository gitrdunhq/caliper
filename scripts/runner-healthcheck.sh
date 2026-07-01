#!/bin/bash
# Runner health check — restart if dead
#
# Install (pick one — all invoke this script unchanged, on a 5-minute cadence):
#
#   1. crontab (any platform):
#        crontab -e
#        */5 * * * * /path/to/runner-healthcheck.sh
#
#   2. launchd (macOS): scripts/com.caliper.runner-healthcheck.plist
#        Edit the plist first — replace both /REPLACE/WITH/ABSOLUTE/PATH/TO/...
#        placeholders (script path + log path; launchd does not expand ~ or
#        env vars) with real absolute paths, then:
#          cp scripts/com.caliper.runner-healthcheck.plist ~/Library/LaunchAgents/
#          launchctl load ~/Library/LaunchAgents/com.caliper.runner-healthcheck.plist
#
#   3. systemd (Linux): scripts/caliper-runner-healthcheck.{service,timer}
#        Edit the .service first — replace the /REPLACE/WITH/ABSOLUTE/PATH/TO/...
#        placeholder with the real absolute path to this script. Installed as a
#        SYSTEM unit (not a user unit) because a CI runner health check needs to
#        run without an interactive login session:
#          sudo cp scripts/caliper-runner-healthcheck.{service,timer} /etc/systemd/system/
#          sudo systemctl enable --now caliper-runner-healthcheck.timer
#        (A user unit under ~/.config/systemd/user/ + `systemctl --user enable
#        --now` also works if the runner user always has a lingering session
#        enabled via `loginctl enable-linger`, but the system unit avoids that
#        extra dependency.)

RUNNER_DIR="$HOME/actions-runner"
LOG="$RUNNER_DIR/healthcheck.log"

if ! pgrep -f "actions-runner/bin/Runner.Listener" > /dev/null 2>&1; then
    echo "$(date): Runner dead — restarting" >> "$LOG"
    cd "$RUNNER_DIR" && nohup ./run.sh >> "$LOG" 2>&1 &
else
    # Check if it's actually processing (last job > 30 min ago = suspicious)
    LAST_JOB=$(tail -1 "$RUNNER_DIR/runner.log" 2>/dev/null | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' || echo "")
    if [ -n "$LAST_JOB" ]; then
        echo "$(date): Runner alive, last activity: $LAST_JOB" >> "$LOG"
    fi
fi
