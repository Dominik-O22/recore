#!/usr/bin/env bash
# Tries land.sh on a repository made for the purpose, under target/land-test: a bare repository
# for GitHub's, a stand-in for the part of `gh` that land.sh uses, and a check.sh that does what a
# file in the change says. It prints each case it tried and exits 1 at the first that went wrong.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="$here/target/land-test"
# The stand-in answers at once, so a landing that waits on it has gone wrong.
export HUB="$work/hub" RUNS="$work/runs" LAND="$here/land.sh" RECORE_CHECK_LOCK="$work/lock" RECORE_LAND_AS_IS=1 RECORE_LAND_PATIENCE=0
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com
rm -rf "$work"
mkdir -p "$work/bin" "$HUB/pr" "$HUB/status" "$HUB/comment" "$HUB/red"
: >"$RUNS"

cat >"$work/bin/gh" <<'EOF'
#!/usr/bin/env bash
# A pull request is a directory of its state, branch and description; a commit's `check` status
# is a file of what it said. A branch named in $HUB/red fails its tests.
set -euo pipefail
git() { command git --git-dir="$HUB/remote.git" "$@"; }
# arg <flag> <arguments>...: what follows that flag.
arg() {
  local flag="$1"
  shift
  while [ $# -gt 1 ]; do
    if [ "$1" = "$flag" ]; then
      echo "$2"
      return
    fi
    shift
  done
}
tip() { git rev-parse "refs/heads/$(cat "$HUB/pr/$1/branch")"; }
# As gh does for an agent, whatever it was asked about a pull request.
if [ "$1" = pr ]; then
  printf 'hint: if you need to wait for this pull request, use this instead of polling:\n    gh event listen\n  - It prints the first event\n' >&2
fi
# What pr.yml does: a change of Markdown alone gets the status without a run.
checked() { [ -e "$HUB/status/$1" ] || [ -z "$(git diff --name-only "main...$1" | grep -v '\.md$')" ]; }
case "$1 $2" in
  "pr view")
    case "$(arg --json "$@")" in
      state) cat "$HUB/pr/$3/state" ;;
      headRefOid) tip "$3" ;;
      headRefName) cat "$HUB/pr/$3/branch" ;;
      baseRefName) echo main ;;
      body) cat "$HUB/pr/$3/body" ;;
    esac
    ;;
  "pr checks")
    tests=pass check=pending
    [ ! -e "$HUB/red/$(cat "$HUB/pr/$3/branch")" ] || tests=fail
    ! checked "$(tip "$3")" || check=pass
    echo "[{\"name\":\"test\",\"bucket\":\"$tests\"},{\"name\":\"budget\",\"bucket\":\"pass\"},{\"name\":\"check\",\"bucket\":\"$check\"}]"
    ;;
  "pr merge")
    head="$(arg --match-head-commit "$@")"
    # As main's protection does: the head that was named, up to date, with its status.
    [ "$(tip "$3")" = "$head" ] && git merge-base --is-ancestor main "$head" && checked "$head"
    commit="$(git commit-tree "$(git merge-tree --write-tree main "$head")" -p main -p "$head" -m "Merge pull request #$3")"
    git update-ref refs/heads/main "$commit"
    # A pull request whose head main now holds is merged, however it got there.
    for pr in "$HUB"/pr/*; do
      if [ "$(cat "$pr/state")" = OPEN ] && git merge-base --is-ancestor "$(tip "${pr##*/}")" main; then
        echo MERGED >"$pr/state"
      fi
    done
    ;;
  "pr create")
    pr=$(($(ls "$HUB/pr" | sort -n | tail -1) + 1))
    mkdir "$HUB/pr/$pr"
    echo OPEN >"$HUB/pr/$pr/state"
    arg --head "$@" >"$HUB/pr/$pr/branch"
    arg --body "$@" >"$HUB/pr/$pr/body"
    echo "https://github.com/sandbox/sandbox/pull/$pr"
    ;;
  "pr close")
    echo CLOSED >"$HUB/pr/$3/state"
    arg --comment "$@" >>"$HUB/comment/$3"
    git update-ref -d "refs/heads/$(cat "$HUB/pr/$3/branch")"
    ;;
  "pr comment") arg --body "$@" >>"$HUB/comment/$3" ;;
  "pr list")
    for pr in "$HUB"/pr/*; do
      if [ "$(cat "$pr/state")" = OPEN ] && [ "$(cat "$pr/branch")" = "$(arg --head "$@")" ]; then
        echo "${pr##*/}"
      fi
    done
    ;;
  api\ *)
    for word in "$@"; do
      case "$word" in
        */required_status_checks/contexts) printf 'test\nbudget\ncheck\n' ;;
        */commits/*/statuses) cat "$HUB/status/$(basename "$(dirname "$word")")" 2>/dev/null || true ;;
        */statuses/*) sha="${word##*/}" ;;
        description=*) echo "${word#description=}" >"$HUB/status/$sha" ;;
      esac
    done
    ;;
  *)
    echo "the stand-in for gh has no: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "$work/bin/gh"
export PATH="$work/bin:$PATH"

git init -q --bare -b main "$work/remote.git"
ln -s "$work/remote.git" "$HUB/remote.git"
git clone -q "$work/remote.git" "$work/clone" 2>/dev/null
cd "$work/clone"
mkdir bench
echo '{"a": {"work": 2}}' >bench/budget.json
echo target/ >.gitignore
cat >check.sh <<'EOF'
#!/usr/bin/env bash
# What a run does is up to the files the change adds: one named `fails`, one that `costs` time
# unless that was accepted, one that `moves` a count, one that `lowers` the budget and one that
# `raises` it. Once, the owner of the branch named in $HUB/pushes pushes to it while the run is
# on, and queues the pull request named in $HUB/queues again.
adds() { [ -n "$(git diff --name-only "$against" HEAD -- "$1")" ]; }
against="$2"
git rev-parse HEAD >>"$RUNS"
if [ -e "$HUB/pushes" ]; then
  branch="$(cat "$HUB/pushes")"
  rm "$HUB/pushes"
  pushed="$(git commit-tree "origin/$branch^{tree}" -p "origin/$branch" -m "Pushed during the run")"
  git push -q origin "$pushed:refs/heads/$branch"
  if [ -e "$HUB/queues" ]; then
    "$LAND" "$(cat "$HUB/queues")" >"$HUB/queued-again" 2>&1 &
    until grep -qs "$pushed" "$(dirname "$RECORE_CHECK_LOCK")/clone/target/landing/queue/$(cat "$HUB/queues")"; do sleep 0.1; done
    rm "$HUB/queues"
  fi
fi
if adds fails; then
  echo "worse than $against: target/corpus/corpus/recore"
  exit 1
fi
if adds costs && [ -z "$RECORE_COST_ACCEPTED" ]; then
  echo "worse than $against: time or memory"
  exit 1
fi
echo "target/corpus/corpus/recore against base/corpus/corpus/recore"
if adds moves; then
  # A gain and a loss that cancel, which the comparison of signatures prints nothing for.
  echo "  parameter types compared in 10 functions, global types in 10 uses"
else
  echo "  no count changed"
fi
! adds lowers || echo '{"a": {"work": 1}}' >bench/budget.json
! adds raises || echo '{"a": {"work": 3}}' >bench/budget.json
[ -n "$(git status --porcelain)" ] || gh api --silent "repos/{owner}/{repo}/statuses/$(git rev-parse HEAD)" -f state=success -f context=check -f description="passed against ${against:0:12}"
EOF
chmod +x check.sh
echo "echo \"main's copy was run with: \$*\"" >land.sh
git add -A
git commit -qm "A repository to land changes in"
git push -q origin HEAD:main

# change <file> [content] [description]: a pull request off main that adds that file. Its number
# is in $pr.
pr=0
change() {
  pr=$((pr + 1))
  while [ -e "$HUB/pr/$pr" ]; do pr=$((pr + 1)); done
  git fetch -q origin
  git checkout -q -B "change-$pr" origin/main
  echo "${2:-$1}" >"$1"
  git add "$1"
  git commit -qm "Add $1"
  git push -q origin "change-$pr"
  mkdir "$HUB/pr/$pr"
  echo OPEN >"$HUB/pr/$pr/state"
  echo "change-$pr" >"$HUB/pr/$pr/branch"
  echo "${3:-}" >"$HUB/pr/$pr/body"
}
# land <pr>...: runs land.sh on them. Its output is in $work/out and its exit status in $status.
land() {
  status=0
  timeout 120 "$here/land.sh" "$@" >"$work/out" 2>&1 || status=$?
}
# is <what> <got> <expected>
is() {
  if [ "$2" != "$3" ]; then
    echo "WRONG: $case: $1 is $2, not $3"
    sed 's/^/    /' "$work/out"
    exit 1
  fi
}
state() { cat "$HUB/pr/$1/state"; }
runs() { wc -l <"$RUNS"; }
trains() { grep -l landing-train "$HUB"/pr/*/branch | wc -l; }
on_main() { git --git-dir="$work/remote.git" show "main:$1" 2>/dev/null; }
tried() { echo "ok: $case"; }

case="two changes land as one train, with one run"
change one && a=$pr
change two && b=$pr
before=$(runs)
land "$a" "$b"
is "the exit status" "$status" 0
is "the first" "$(state "$a")" MERGED
is "the second" "$(state "$b")" MERGED
is "the runs of check.sh" "$(($(runs) - before))" 1
is "main's files" "$(on_main one)$(on_main two)" onetwo
is "the lines of gh's hints in what it printed" "$(grep -c '^hint\|gh event listen\|It prints' "$work/out")" 0
tried

case="a train whose run moved a count lands its members one at a time, the second on top of the first"
change moves && a=$pr
change three && b=$pr
before=$(runs)
land "$a" "$b"
is "the exit status" "$status" 0
is "the one that moved a count" "$(state "$a")" MERGED
is "the other" "$(state "$b")" MERGED
is "the runs of check.sh" "$(($(runs) - before))" 3
is "the parents of the second's head, main merged into it" "$(git --git-dir="$work/remote.git" rev-list --parents -1 "change-$b" | wc -w)" 3
tried

case="a member that fails is turned away and told why, and the other lands"
change fails && a=$pr
change four && b=$pr
land "$a" "$b"
is "the exit status" "$status" 1
is "the one that fails" "$(state "$a")" OPEN
is "what it was told" "$(grep -c 'check.sh failed' "$HUB/comment/$a")" 1
is "the other" "$(state "$b")" MERGED
echo CLOSED >"$HUB/pr/$a/state"
tried

case="of two that conflict, one lands and the other is told to merge main"
change same first && a=$pr
change same second && b=$pr
land "$a" "$b"
is "the exit status" "$status" 1
is "the first" "$(state "$a")" MERGED
is "the second" "$(state "$b")" OPEN
is "what it was told" "$(grep -c 'conflicts with main' "$HUB/comment/$b")" 1
echo CLOSED >"$HUB/pr/$b/state"
tried

case="a budget the run lowered is committed and lands without a second run"
change lowers && a=$pr
before=$(runs)
land "$a"
is "the exit status" "$status" 0
is "the change" "$(state "$a")" MERGED
is "the runs of check.sh" "$(($(runs) - before))" 1
is "main's budget" "$(on_main bench/budget.json)" '{"a": {"work": 1}}'
tried

case="a change with a Budget: line lands alone"
change five five "Budget: the lookups grew, to keep edits in step" && a=$pr
change six && b=$pr
before=$(runs) trains_before=$(trains)
land "$a" "$b"
is "the exit status" "$status" 0
is "both" "$(state "$a")$(state "$b")" MERGEDMERGED
is "the runs of check.sh" "$(($(runs) - before))" 2
is "the trains opened" "$(($(trains) - trains_before))" 0
tried

case="a change check.sh reads nothing of lands without a run"
change notes.md && a=$pr
before=$(runs)
land "$a"
is "the exit status" "$status" 0
is "the change" "$(state "$a")" MERGED
is "the runs of check.sh" "$(($(runs) - before))" 0
tried

case="a cost that was accepted is accepted for that change alone"
change costs && a=$pr
change twelve && b=$pr
before=$(runs) trains_before=$(trains)
land --accept-cost "$a"
land "$b"
is "both" "$(state "$a")$(state "$b")" MERGEDMERGED
is "the runs of check.sh" "$(($(runs) - before))" 2
change costs again && a=$pr
land "$a"
is "the exit status of one whose cost was not accepted" "$status" 1
is "what it was told" "$(grep -c 'time or memory' "$HUB/comment/$a")" 1
echo CLOSED >"$HUB/pr/$a/state"
tried

case="a change whose tests fail is turned away"
change seven && a=$pr
touch "$HUB/red/change-$a"
land "$a"
is "the exit status" "$status" 1
is "the change" "$(state "$a")" OPEN
is "what it was told" "$(grep -c 'test failed' "$HUB/comment/$a")" 1
echo CLOSED >"$HUB/pr/$a/state"
tried

case="a head that moved after it was queued is turned away"
change eight && a=$pr
exec 8>"$RECORE_CHECK_LOCK"
flock 8
"$here/land.sh" "$a" >"$work/out" 2>&1 &
until [ -e "$work/clone/target/landing/queue/$a" ]; do sleep 0.1; done
echo more >>eight
git commit -qam "Add to eight"
git push -q origin "change-$a"
flock -u 8
status=0
wait $! || status=$?
is "the exit status" "$status" 1
is "the change" "$(state "$a")" OPEN
is "what it was told" "$(grep -c 'its head moved' "$HUB/comment/$a")" 1
tried

case="a change pushed to while it is checked is turned away at once, and the push can be queued"
change nine && a=$pr
echo "change-$a" >"$HUB/pushes"
land "$a"
is "the exit status" "$status" 1
is "the change" "$(state "$a")" OPEN
is "what it was told" "$(grep -c 'its head moved .* was landing' "$HUB/comment/$a")" 1
land "$a"
is "the exit status the second time" "$status" 0
is "the change, queued again" "$(state "$a")" MERGED
tried

case="a change queued again while it lands keeps its place, and lands at its new head"
change sixteen && a=$pr
echo "change-$a" >"$HUB/pushes"
echo "$a" >"$HUB/queues"
land "$a"
is "the change" "$(state "$a")" MERGED
until grep -qs "^#$a landed" "$HUB/queued-again"; do sleep 0.1; done
tried

case="a run that raised the budget is turned away"
change raises && a=$pr
land "$a"
is "the exit status" "$status" 1
is "what it was told" "$(grep -c 'left changes behind' "$HUB/comment/$a")" 1
echo CLOSED >"$HUB/pr/$a/state"
tried

case="a member pushed to while its train lands is told so, and the other lands"
change ten && a=$pr
change eleven && b=$pr
echo "change-$a" >"$HUB/pushes"
land "$a" "$b"
is "the exit status" "$status" 1
is "the one that was pushed to" "$(state "$a")" OPEN
is "what it was told" "$(grep -c 'landed what was queued .* its head has moved' "$HUB/comment/$a")" 1
is "the other" "$(state "$b")" MERGED
echo CLOSED >"$HUB/pr/$a/state"
tried

case="nothing is queued when one of the arguments is not a pull request"
change thirteen && a=$pr
land "$a" 1x
is "the exit status" "$status" 2
is "what is queued" "$(ls "$work/clone/target/landing/queue")" ""
echo CLOSED >"$HUB/pr/$a/state"
tried

case="a checkout runs main's copy of land.sh"
status=0
RECORE_LAND_AS_IS='' "$here/land.sh" 7 8 >"$work/out" 2>&1 || status=$?
is "what ran" "$(cat "$work/out")" "main's copy was run with: 7 8"
tried

case="a train left open by a landing that ended early is closed, and its members land"
change fourteen && a=$pr
change fifteen && b=$pr
git push -q origin "change-$a:landing-train"
mkdir "$HUB/pr/900"
echo OPEN >"$HUB/pr/900/state"
echo landing-train >"$HUB/pr/900/branch"
: >"$HUB/pr/900/body"
before=$(runs)
land "$a" "$b"
is "the exit status" "$status" 0
is "the train that was left" "$(state 900)" CLOSED
is "both" "$(state "$a")$(state "$b")" MERGEDMERGED
is "the runs of check.sh" "$(($(runs) - before))" 1
tried
