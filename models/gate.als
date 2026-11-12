-- The caller gate in kmsproxy/gate: rules, queued requests and grouped prompts.
-- The attacker is every caller: it opens and drops connections for any domain, and
-- answers prompts by replacing the notification (random action keys make that a
-- dismissal). Only the user allows anything.
module gate

sig Caller {}
sig Domain {}

-- A client connection asking for a domain
sig Request {
  caller: one Caller,
  domain: one Domain,
  var status: lone Status
}

abstract sig Status {}
one sig Waiting, Forwarded, Refused, Gone extends Status {}

-- A prompt shows a caller and the domains it waits on, frozen when shown
sig Prompt {
  pcaller: one Caller,
  var shown: set Domain
}

var sig Open in Prompt {}
var sig Used in Prompt {}
-- Prompts the user (or a replacement) has answered: each gets one answer
var sig Answered in Prompt {}

-- Rules: allowed holds "Always allow" and "Allow for 1 hour", denied holds "Deny" (1 hour).
-- Ghosts: seen is what prompts showed the user, consent what the user allowed
one sig G {
  var allowed, denied, seen, consent: Caller -> Domain
}
fun Allowed: Caller -> Domain { G.allowed }
fun Denied: Caller -> Domain { G.denied }
fun Seen: Caller -> Domain { G.seen }
fun Consent: Caller -> Domain { G.consent }

fact init {
  no status
  no Open
  no Used
  no Answered
  no shown
  no G.allowed + G.denied + G.seen + G.consent
}

pred unchanged[r: set Request] { all x: r | x.status' = x.status }
pred keepRules { G.allowed' = Allowed and G.denied' = Denied }
pred keepPrompts { Open' = Open and Used' = Used and shown' = shown and Answered' = Answered }
pred keepGhosts { G.seen' = Seen and G.consent' = Consent }

-- Gate.Check: a rule decides at once, otherwise the request waits
pred arrive[r: Request] {
  no r.status
  r.caller -> r.domain in Allowed implies r.status' = Forwarded
  else r.caller -> r.domain in Denied implies r.status' = Refused
  else r.status' = Waiting
  unchanged[Request - r]
  keepRules and keepPrompts and keepGhosts
}

fun waitingDomains[c: Caller]: set Domain {
  { d: Domain | some r: Request | r.status = Waiting and r.caller = c and r.domain = d }
}

-- One open prompt per caller, showing every domain it waits on
pred show[p: Prompt] {
  p not in Used
  no (Open & pcaller.(p.pcaller))
  some waitingDomains[p.pcaller]
  shown' = shown + p -> waitingDomains[p.pcaller]
  Open' = Open + p
  Used' = Used + p
  G.seen' = Seen + p.pcaller -> waitingDomains[p.pcaller]
  G.consent' = Consent
  unchanged[Request]
  keepRules
}

-- The requests a prompt answers: its caller's, for the domains it shows
fun answers[p: Prompt]: set Request {
  { r: Request | r.status = Waiting and r.caller = p.pcaller and r.domain in p.shown }
}

pred allow[p: Prompt] {
  p in Open
  p not in Answered
  Answered' = Answered + p
  G.allowed' = Allowed + p.pcaller -> p.shown
  G.denied' = Denied - p.pcaller -> p.shown
  G.consent' = Consent + p.pcaller -> p.shown
  all r: answers[p] | r.status' = Forwarded
  unchanged[Request - answers[p]]
  Open' = Open - p and Used' = Used and shown' = shown and G.seen' = Seen
}

pred deny[p: Prompt] {
  p in Open
  p not in Answered
  Answered' = Answered + p
  G.denied' = Denied + p.pcaller -> p.shown
  G.allowed' = Allowed - p.pcaller -> p.shown
  all r: answers[p] | r.status' = Refused
  unchanged[Request - answers[p]]
  Open' = Open - p and Used' = Used and shown' = shown
  keepGhosts
}

-- Closed unanswered, a replacement clicked, or a server error: refuse, no rule
pred dismiss[p: Prompt] {
  p in Open
  p not in Answered
  Answered' = Answered + p
  all r: answers[p] | r.status' = Refused
  unchanged[Request - answers[p]]
  Open' = Open - p and Used' = Used and shown' = shown
  keepRules and keepGhosts
}

-- The client disconnects, or waits out its 2 minutes
pred leave[r: Request] {
  r.status = Waiting
  r.status' = Gone
  unchanged[Request - r]
  keepRules and keepPrompts and keepGhosts
}

-- A prompt nobody waits on any more is taken down
pred withdraw[p: Prompt] {
  p in Open
  no answers[p]
  Open' = Open - p and Used' = Used and shown' = shown and Answered' = Answered
  unchanged[Request]
  keepRules and keepGhosts
}

-- Gate.answer for a withdrawn prompt: the user answers after it was taken down. Its rules apply, and
-- requests they now decide are settled by them (Gate.settle)
fun decidedBy[c: Caller, ds: set Domain]: set Request {
  { r: Request | r.status = Waiting and r.caller = c and r.domain in ds }
}
pred lateAllow[p: Prompt] {
  p in Used - Open
  p not in Answered
  Answered' = Answered + p
  G.allowed' = Allowed + p.pcaller -> p.shown
  G.denied' = Denied - p.pcaller -> p.shown
  G.consent' = Consent + p.pcaller -> p.shown
  all r: decidedBy[p.pcaller, p.shown] | r.status' = Forwarded
  unchanged[Request - decidedBy[p.pcaller, p.shown]]
  Open' = Open and Used' = Used and shown' = shown and G.seen' = Seen
}
pred lateDeny[p: Prompt] {
  p in Used - Open
  p not in Answered
  Answered' = Answered + p
  G.denied' = Denied + p.pcaller -> p.shown
  G.allowed' = Allowed - p.pcaller -> p.shown
  all r: decidedBy[p.pcaller, p.shown] | r.status' = Refused
  unchanged[Request - decidedBy[p.pcaller, p.shown]]
  Open' = Open and Used' = Used and shown' = shown
  keepGhosts
}

-- Temporary rules run out
pred expire[c: Caller, d: Domain] {
  c -> d in Allowed + Denied
  G.allowed' = Allowed - c -> d
  G.denied' = Denied - c -> d
  unchanged[Request]
  keepPrompts and keepGhosts
}

pred stutter {
  unchanged[Request]
  keepRules and keepPrompts and keepGhosts
}

fact traces {
  always (
    (some r: Request | arrive[r] or leave[r]) or
    (some p: Prompt | show[p] or allow[p] or deny[p] or dismiss[p] or withdraw[p] or lateAllow[p] or lateDeny[p]) or
    (some c: Caller, d: Domain | expire[c, d]) or
    stutter
  )
}

-- Forwarded only what the user allowed for that caller
assert forwardedWithConsent {
  always all r: Request | r.status = Forwarded implies r.caller -> r.domain in Consent
}
check forwardedWithConsent for 3 but 4 Request, 1..12 steps expect 0

-- The user allows only what a prompt showed
assert consentShown {
  always Consent in Seen
}
check consentShown for 3 but 4 Request, 1..12 steps expect 0

-- One open prompt per caller
assert onePromptPerCaller {
  always all c: Caller | lone (Open & pcaller.c)
}
check onePromptPerCaller for 3 but 4 Request, 1..12 steps expect 0

-- A decided or abandoned request stays so
assert final {
  always all r: Request | (some r.status and r.status in Forwarded + Refused + Gone) implies always r.status' = r.status
}
check final for 3 but 4 Request, 1..12 steps expect 0

-- Vacuity: each action happens, and the interesting traces exist
run forwardAfterPrompt {
  eventually some p: Prompt | allow[p] and some answers[p]
} for 3 but 4 Request, 1..12 steps expect 1
run groupedAnswer {
  eventually some p: Prompt | #p.shown > 1 and allow[p]
} for 3 but 4 Request, 1..12 steps expect 1
run laterArrivalJoinsShown {
  some p: Prompt, r: Request | eventually (p in Open and r.domain in p.shown and no r.status and after (r.status = Waiting and after allow[p]))
} for 3 but 4 Request, 1..12 steps expect 1
run laterDomainWaits {
  some p: Prompt, r: Request | eventually (p in Open and r.caller = p.pcaller and r.domain not in p.shown and r.status = Waiting and after (allow[p] and after r.status = Waiting))
} for 3 but 4 Request, 1..12 steps expect 1
run deniedRemembered {
  some r: Request | eventually (arrive[r] and r.caller -> r.domain in Denied and after r.status = Refused)
} for 3 but 4 Request, 1..12 steps expect 1
run withdrawn { eventually some p: Prompt | withdraw[p] } for 3 but 4 Request, 1..12 steps expect 1
run dismissed { eventually some p: Prompt | dismiss[p] } for 3 but 4 Request, 1..12 steps expect 1
run lateAnswerSettles {
  eventually some p: Prompt | lateAllow[p] and some decidedBy[p.pcaller, p.shown]
} for 3 but 4 Request, 1..12 steps expect 1
run expired { eventually some c: Caller, d: Domain | expire[c, d] } for 3 but 4 Request, 1..12 steps expect 1
