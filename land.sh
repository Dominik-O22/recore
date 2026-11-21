#!/usr/bin/env bash
# How a pull request gets into main: `./land.sh <pr>...` queues them and lands every queued pull
# request, whoever queued it. Run it once the change is reviewed, pushed, and passed
# `./check.sh --quick --against origin/main`. It ends when the ones it was given have landed or
# were turned away, says which, and exits 1 if any was turned away. A landing takes as long as a
# run of check.sh and the tests on GitHub, so start it in the background.
#
# One landing runs at a time on this machine, under the lock every heavy run takes
# (~/.cache/recore-check.lock, or $RECORE_CHECK_LOCK), and it holds the lock from reading main to
# the merge. So main cannot move under a check, and a change is checked once, against the main it
# lands on. It takes the lock itself: run under `flock` on that file, it would wait for its own
# caller.
#
#   - One pull request: main is merged into its branch if the branch is behind,
#     `./check.sh --against` runs on the result, and it is merged once the checks main requires
#     are green.
#   - Two or more: they are merged together onto main as a train, which is opened as a pull
#     request of its own, and one run of check.sh answers for all of them. Merging the train
#     merges them. A train lands only if its run moved no count, since what one change gained
#     would hide what another lost, and a change that moves a count has to say which. When the
#     run moved one or failed, and when a member conflicts, they land one at a time instead, each
#     checked on top of the last.
#   - A pull request whose description has a `Budget:` line, or that was queued with
#     `--accept-cost` (its check then runs with RECORE_COST_ACCEPTED=1), lands alone, so that what
#     it was let past is not let past for another.
#   - So does one whose description has `Worse:` lines, which name the losses its check accepts:
#     the check runs with the description as RECORE_WORSE_ACCEPTED, and fails on a loss no line
#     names and on a line that names no loss of the run. A train's one run could not say whose
#     loss it was.
#
# A run that lowered bench/budget.json and changed nothing else is committed here, and that commit
# gets the status without a run of its own: it differs from the commit that passed only in the
# numbers that run measured.
#
# The checks run in one checkout that is kept between landings, target/landing/tree of the main
# checkout, so its build stays warm. Each run's output is in target/landing/log.
set -euo pipefail
# Every checkout runs main's copy, so that one branched long ago lands by today's rules.
# RECORE_LAND_AS_IS=1 runs this file instead, which is how a change to it is tried.
if [ -z "${RECORE_LAND_AS_IS:-}" ] && git fetch -q origin && git cat-file -e origin/main:land.sh 2>/dev/null; then
  RECORE_LAND_AS_IS=1 exec bash -c "$(git show origin/main:land.sh)" land.sh "$@"
fi
flags=
if [ "${1:-}" = --accept-cost ]; then
  flags=cost
  shift
fi
if [ $# -eq 0 ]; then
  echo "usage: ./land.sh [--accept-cost] <pr>..." >&2
  exit 2
fi
# What every worktree of this repository shares is under the main checkout's target/.
state="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")/target/landing"
queue="$state/queue" answers="$state/answer" logs="$state/log" tree="$state/tree"
lock="${RECORE_CHECK_LOCK:-$HOME/.cache/recore-check.lock}"
# How many seconds GitHub gets to answer with the checks main requires.
patience="${RECORE_LAND_PATIENCE:-2700}"
train_branch=landing-train
mkdir -p "$queue" "$answers" "$logs" "$(dirname "$lock")"

# Asked about a pull request by an agent, gh adds eight lines on stderr on how to wait for one: a
# line that starts `hint:` and indented ones under it. A landing asks every few seconds, so those
# lines are left out of what gh says there, and what went wrong still shows.
gh() { command gh "$@" 2> >(grep -v '^hint: \|^  ' >&2); }
# field <pr> <name>: one fact about a pull request.
field() { gh pr view "$1" --json "$2" -q ".$2"; }
# need <answer> <what>: stops the landing, with the queue as it is, when gh gave no answer. Going
# on would turn a pull request away for what GitHub never said. If this landing had already
# pushed to the pull request it was on, the next one turns that away for a head that moved.
need() {
  if [ -z "$1" ]; then
    echo "land.sh: gh did not say $2, so this landing stops and what is queued stays queued" >&2
    exit 1
  fi
}

for pr in "$@"; do
  if ! [[ "$pr" =~ ^[0-9]+$ ]] || [ "$(field "$pr" state)" != OPEN ] || [ "$(field "$pr" baseRefName)" != main ]; then
    echo "$pr is not an open pull request into main, so nothing was queued" >&2
    exit 2
  fi
done
# A queued pull request is a file named after it: the head that was queued, then `cost` if its
# cost was accepted. Queued again, it is a new file, at the head it has by then.
for pr in "$@"; do
  head="$(field "$pr" headRefOid)"
  need "$head" "the head of #$pr"
  rm -f "$answers/$pr"
  printf '%s\n%s\n' "$head" "$flags" >"$queue/.$pr"
  mv "$queue/.$pr" "$queue/$pr"
done

# Left open for check.sh too, so that a run this script died under still keeps the next landing
# out of its checkout.
exec 9>"$lock"
flock 9

# The head each pull request of this pass was queued at, and the ones that have to land outside
# a train.
declare -A heads=() alone=()

# finish <pr> <landed|turned away> <why>: leaves the answer for the run that queued it and takes
# it off the queue, unless it was queued again meanwhile: that is the next pass's. A pull request
# that was turned away is told why, which is what wakes its owner.
finish() {
  echo "#$1 $2: $3"
  echo "$2: $3" >"$answers/$1"
  if [ "$(sed -n 1p "$queue/$1" 2>/dev/null)" = "${heads[$1]}" ]; then
    rm -f "$queue/$1"
  fi
  if [ "$2" != landed ]; then
    gh pr comment "$1" --body "\`land.sh\` did not land this: $3" >/dev/null
  fi
}

# current <pr>: whether it is still open at the head that was queued. If not, that is its answer.
current() {
  local head state
  heads[$1]="$(sed -n 1p "$queue/$1")"
  head="$(field "$1" headRefOid)" state="$(field "$1" state)"
  need "$head" "the head of #$1"
  need "$state" "whether #$1 is open"
  case "$state" in
    MERGED) finish "$1" landed "it was merged already" ;;
    OPEN)
      [ "$head" != "${heads[$1]}" ] || return 0
      finish "$1" "turned away" "its head moved to ${head:0:12} after it was queued at ${heads[$1]:0:12}, so queue it again"
      ;;
    *) finish "$1" "turned away" "it was closed" ;;
  esac
  return 1
}

# rides <pr>: whether it may share a train.
rides() {
  local body
  body="$(field "$1" body)"
  [ -z "${alone[$1]:-}" ] && [ -z "$(sed -n 2p "$queue/$1")" ] && ! grep -Eq '^Budget: .+|^Worse:' <<<"$body"
}

# at <commit>: the landing checkout at that commit, with nothing left of an earlier run but its
# build.
at() {
  if [ ! -e "$tree/.git" ]; then
    git worktree prune
    git worktree add -q --detach "$tree" "$1"
  fi
  git -C "$tree" merge --abort 2>/dev/null || true
  git -C "$tree" reset -q --hard
  git -C "$tree" clean -qfd
  git -C "$tree" checkout -q --detach "$1"
}

# reads <head>: whether check.sh reads anything the change to main touches. The rule is pr.yml's,
# which gives the status itself to a change that touches none of it. Not `grep -q`, which stops
# reading at the first line and so fails the pipe before it.
reads() { [ -n "$(git diff --no-renames --name-only "$base" "$1" | grep -Ev '^player/|\.md$|^\.coderabbit\.yaml$')" ]; }

# green <pr> <head>: waits for every check main requires to pass on that head. Fails, and says why
# in $why, when one failed, when the head moved, or when $patience brought no answer.
green() {
  local required checks head seen='' waited=0
  required="$(gh api "repos/{owner}/{repo}/branches/main/protection/required_status_checks/contexts" --jq '.[]' | sort)"
  need "$required" "which checks main requires"
  while :; do
    # No answer from gh is not an answer about the head, so it only uses up patience.
    head="$(field "$1" headRefOid || true)"
    if [ -n "$head" ] && [ "$head" != "$2" ]; then
      # GitHub takes a moment to see a push, and until then it answers for the head before it.
      if [ -n "$seen" ] || [ "$waited" -ge 60 ] || [ "$waited" -ge "$patience" ]; then
        why="its head moved to ${head:0:12} while ${2:0:12} was landing, so queue it again"
        return 1
      fi
    elif [ -n "$head" ]; then
      seen=1
      checks="$(gh pr checks "$1" --required --json name,bucket 2>/dev/null || true)"
      why="$(jq -r '[.[] | select(.bucket == "fail" or .bucket == "cancel") | .name] | unique | join(", ")' <<<"${checks:-[]}")"
      if [ -n "$why" ]; then
        why="on ${2:0:12}, $why failed"
        return 1
      fi
      [ "$(jq -r '.[] | select(.bucket == "pass") | .name' <<<"${checks:-[]}" | sort -u)" != "$required" ] || return 0
    fi
    if [ "$waited" -ge "$patience" ]; then
      why="the checks main requires gave no answer on ${2:0:12} in $((patience / 60)) minutes"
      return 1
    fi
    sleep 20
    waited=$((waited + 20))
  done
}

# settle <pr> <its branch> <its flags> [train]: checks and merges the pull request whose head the
# landing checkout is at, a head that holds main. Fails, and says why in $why, when it did not
# merge. A train's run also fails when it moved a count.
settle() {
  local pr="$1" branch="$2" cost='' log="$logs/$1.log" head body dirty grew compared passed accepted tries=0
  [[ "$3" != *cost* ]] || cost=1
  head="$(git -C "$tree" rev-parse HEAD)"
  if reads "$head"; then
    body="$(field "$pr" body)" || need "" "the description of #$pr"
    echo "#$pr: check.sh on ${head:0:12} against ${base:0:12}, its output in $log"
    if ! (cd "$tree" && RECORE_COST_ACCEPTED="$cost" RECORE_WORSE_ACCEPTED="$body" ./check.sh --against "$base") >"$log" 2>&1; then
      why="check.sh failed on ${head:0:12} against ${base:0:12}: $(grep '^worse' "$log" | tail -1 || true) ($log)"
      return 1
    fi
    # Every comparison check.sh makes is headed `<this run> against <the base's>`, and says
    # `no count changed` when none did. A run with no comparison to count is not one to trust.
    compared="$(grep -Ec '^target/corpus/[^ ]+ against ' "$log" || true)"
    if [ -n "${4:-}" ] && { [ "$compared" -eq 0 ] || [ "$compared" != "$(grep -c '^  no count changed' "$log" || true)" ]; }; then
      why="the run moved a count ($log)"
      return 1
    fi
    dirty="$(git -C "$tree" status --porcelain)"
    if [ -n "$dirty" ]; then
      # check.sh leaves no status on a commit whose budget it lowered. Numbers that only went
      # down are the ones this run measured, so the commit that holds them needs no run.
      why="its run of check.sh left changes behind, so commit them and queue it again: $(tr '\n' ' ' <<<"$dirty")"
      [ "$dirty" = " M bench/budget.json" ] || return 1
      grew="$(git -C "$tree" show HEAD:bench/budget.json | jq -r --slurpfile now "$tree/bench/budget.json" '. as $was | $now[0] | paths(numbers) as $p | select(($was | getpath($p)) as $old | $old == null or getpath($p) > $old) | $p | join(" ")')" || return 1
      [ -z "$grew" ] || return 1
      git -C "$tree" commit -qam "Lower the instruction budget where the ratchet measured less"
      head="$(git -C "$tree" rev-parse HEAD)"
      why="its branch moved while ${head:0:12} was landing, so queue it again"
      git -C "$tree" push -q origin "HEAD:refs/heads/$branch" 2>/dev/null || return 1
      # As check.sh says it, with the losses the run accepted.
      passed="passed against ${base:0:12}"
      accepted="$(grep -c '^  accepted ' "$log" || true)"
      [ "$accepted" -eq 0 ] || passed+=", accepting $accepted named loss$([ "$accepted" -eq 1 ] || echo es)"
      gh api --silent "repos/{owner}/{repo}/statuses/$head" -f state=success -f context=check -f description="$passed, before the budget it lowered" || return 1
    fi
  fi
  green "$pr" "$head" || return 1
  # GitHub can take a few seconds after the last check to call a pull request mergeable.
  until gh pr merge "$pr" --merge --match-head-commit "$head" >"$logs/$pr.merge" 2>&1; do
    # An attempt that merged it and then lost its answer is not one to make again.
    [ "$(field "$pr" state || true)" != MERGED ] || break
    tries=$((tries + 1))
    if [ "$tries" -ge 6 ] || [ "$((tries * 10))" -gt "$patience" ]; then
      why="GitHub would not merge ${head:0:12}: $(tr '\n' ' ' <"$logs/$pr.merge")"
      return 1
    fi
    sleep 10
  done
}

# single <pr>: lands it on its own, with main merged into its branch first when it is behind.
single() {
  local pr="$1" branch
  branch="$(field "$pr" headRefName)"
  at "${heads[$pr]}"
  if ! git merge-base --is-ancestor "$base" "${heads[$pr]}"; then
    if ! git -C "$tree" merge -q --no-edit -m "Merge branch 'main' into $branch" "$base" >/dev/null 2>&1; then
      finish "$pr" "turned away" "it conflicts with main at ${base:0:12}, so merge main into it and queue it again"
      return
    fi
    if ! git -C "$tree" push -q origin "HEAD:refs/heads/$branch" 2>/dev/null; then
      finish "$pr" "turned away" "its branch moved while main was merged into it, so queue it again"
      return
    fi
  fi
  if settle "$pr" "$branch" "$(sed -n 2p "$queue/$pr")"; then
    finish "$pr" landed "on main at ${base:0:12}"
  else
    finish "$pr" "turned away" "$why"
  fi
}

# train <pr>...: lands them with one check, or leaves them to land alone.
train() {
  local pr aboard=() url head
  at "$base"
  for pr in "$@"; do
    if git -C "$tree" merge -q --no-ff -m "Merge pull request #$pr from $(field "$pr" headRefName)" "${heads[$pr]}" >/dev/null 2>&1; then
      aboard+=("$pr")
    else
      git -C "$tree" merge --abort 2>/dev/null || true
    fi
    # Whatever becomes of the train, none of them rides another in this landing.
    alone[$pr]=1
  done
  [ ${#aboard[@]} -ge 2 ] || return 0
  git -C "$tree" push -qf origin "HEAD:refs/heads/$train_branch" 2>/dev/null || return 0
  url="$(gh pr create --head "$train_branch" --base main --title "Land $(printf '#%s ' "${aboard[@]}" | sed 's/ $//; s/ /, /g')" --body "A train from \`land.sh\`: these pull requests merged together onto main at ${base:0:12}, with one run of \`check.sh\` for all of them. Merging it merges them.")" || return 0
  if ! settle "${url##*/}" "$train_branch" "" train; then
    echo "train #${url##*/}: $why, so its members land one at a time"
    gh pr close "${url##*/}" --delete-branch --comment "$why, so its members land one at a time." >/dev/null
    return 0
  fi
  git push -q origin --delete "$train_branch" 2>/dev/null || true
  for pr in "${aboard[@]}"; do
    # Main holds what was queued. A member whose owner pushed to it while the train was landing
    # stays open on GitHub, with what was pushed.
    head="$(field "$pr" headRefOid || true)"
    if [ -n "$head" ] && [ "$head" != "${heads[$pr]}" ]; then
      finish "$pr" "turned away" "train #${url##*/} landed what was queued at ${heads[$pr]:0:12}, but its head has moved to ${head:0:12} since, so queue it again"
    else
      finish "$pr" landed "in train #${url##*/} on main at ${base:0:12}"
    fi
  done
}

while :; do
  queued=()
  for pr in $(ls "$queue" | sort -n); do queued+=("$pr"); done
  [ ${#queued[@]} -gt 0 ] || break
  git fetch -q origin
  base="$(git rev-parse origin/main)"
  # Only the landing that holds the lock has a train, so one that is open now was left by a
  # landing that ended early.
  for pr in $(gh pr list --head "$train_branch" --state open --json number -q '.[].number'); do
    gh pr close "$pr" --delete-branch --comment "The landing that opened this train ended before it merged." >/dev/null
  done
  open=() riders=()
  for pr in "${queued[@]}"; do
    current "$pr" || continue
    open+=("$pr")
    ! rides "$pr" || riders+=("$pr")
  done
  if [ ${#riders[@]} -ge 2 ]; then
    train "${riders[@]}"
  elif [ ${#open[@]} -gt 0 ]; then
    single "${open[0]}"
  fi
done
flock -u 9

turned_away=0
for pr in "$@"; do
  if ! grep -s '^landed' "$answers/$pr" >/dev/null; then
    turned_away=1
  fi
  echo "#$pr $(cat "$answers/$pr" 2>/dev/null || echo "has no answer: the landing that took it ended early, so queue it again")"
done
exit "$turned_away"
