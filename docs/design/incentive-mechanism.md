---
title: "Harvest: A Marketplace Without a Referee"
subtitle: "How to make fraud unprofitable when nobody can tell who is lying"
date: "29 August 2026"
---

# Part 1 — The setting, and the problem

## What Freenet is

Freenet is a decentralised platform. There are no servers in the usual sense: every participant runs a node, and those nodes collectively store data and route requests. Applications are built from three kinds of component.

**Contracts** hold shared state on the network. A contract is a small piece of code that defines what counts as valid state and how two versions of that state merge together. The state itself is public, held by whichever peers happen to store it, and any peer can be asked for it.

**Delegates** run locally, inside the user's own node. A delegate holds private data — keys, secrets, preferences — and can sign things on the user's behalf. It is the user's agent.

**A user interface**, usually a web page, talks to the local node and presents all of this to a person.

The important consequence is that there is no operator. No company runs Freenet, no server holds the authoritative copy, and no administrator can intervene in anything.

## What Harvest is

Harvest is a marketplace application for Freenet. Sellers list goods, buyers find them, and the two arrange a purchase. Payment happens outside the system entirely — the seller names a method and the buyer pays them directly.

## The problem this document is about

Every marketplace that works has something Harvest does not: a referee. When a buyer says the goods never arrived and the seller says they did, somebody has to decide. eBay and Amazon look at tracking numbers and messages and rule. A credit card network reverses the charge. An escrow agent holds the money until both sides agree.

Harvest has none of that, and cannot have it. There is no operator to arbitrate, no way to reverse a payment, and — this is the hard part — **no way for the system to observe whether a parcel arrived**. There is no sensor, no data feed, no cryptographic proof of a physical delivery. There never will be.

So the design cannot aim to resolve disputes correctly. It has to aim at something else: making dishonesty unprofitable *without ever determining who was dishonest*.

That single constraint explains every unusual feature of what follows.

# Part 2 — Ghostkeys: identity that costs money

Harvest's identities are called ghostkeys, and they come from a separate Freenet project.

A ghostkey is created by donating money to Freenet. In exchange the donor receives a cryptographic certificate. Three properties matter:

**The donation amount is attested and cannot be forged.** The certificate records the amount, signed in a chain leading back to a master key that everyone can verify. A $500 ghostkey provably cost $500.

**The identity is unlinkable to the donation.** Creation uses a blind signature, meaning the issuing server signs the new identity without being able to see it. So the issuer cannot connect the person who paid to the identity that resulted.

**It is nonetheless persistent.** It is a stable pseudonym. Things can accumulate against it, and it can build a history.

The essential point is that identities cost real money. Creating one costs a donation; creating a thousand costs a thousand donations. That makes identity scarce, which is unusual online and is the foundation everything else is built on.

# Part 3 — The first design, and the three ways it fails

## The original sketch

The initial idea was straightforward. A seller's ghostkey donation is their **bond** — the value they lose if their reputation is ruined, because a ruined pseudonym has to be replaced at cost. When a buyer commits to a purchase, the seller privately hands over payment instructions together with a **claim**: a statement, signed with the seller's own key, saying *"I failed to deliver this order."*

The buyer holds it. If the goods arrive, the claim is thrown away and nothing is ever published. If they do not, the buyer publishes it to the seller's public reputation record, where future buyers will see it. The seller cannot deny it, because it carries their own signature.

Reputation is therefore negative-only, and a successful transaction leaves no trace at all.

It is an appealing design. It also fails, in three independent ways.

## Failure 1: the bond is an entry fee, not a stake

Because feedback is negative-only and success is silent, a brand-new ghostkey and a five-year-old one with a spotless record present *identical* public records. There is nothing to accumulate. A clean history is indistinguishable from no history.

So when a seller's pseudonym is ruined, what they lose is exactly the cost of a replacement. Not accumulated goodwill — there is none.

This breaks the standard argument for why reputation makes people honest. That argument says a merchant stays honest because cheating would forfeit a stream of future business worth more than the one-time gain. Here, cheating forfeits only the replacement cost, because the future business simply reattaches to a fresh identity. The deterrent is capped at the price of a new pseudonym, and re-entry is instant and perfect.

## Failure 2: the exit scam, and a hard ceiling on the whole market

Orders are private until something goes wrong, so no buyer can see how many orders a seller currently has open.

That permits the exit scam: trade honestly until order volume builds up, then defect on every open order at once and abandon the identity.

The arithmetic is simple. If each order is worth $100 and the seller's margin is 20%, then defecting rather than fulfilling gains an extra $80 per order. Against a $500 bond, defection pays once seven orders are open simultaneously — a level any modestly successful seller reaches easily.

The consequence is worse than the attack itself. Rational buyers understand this and limit their exposure accordingly, so the market settles at a point where no seller can safely carry more than roughly their bond's worth of open orders. **At the largest available donation tier that is around $1,250 of open orders — ever, regardless of history.**

Growth makes defection more attractive, buyers price that in, and success becomes self-limiting. The design has a smallness bound built into it.

## Failure 3: deterrence and extortion are the same number

This one bounds every design of this shape, so it is worth stating carefully.

Suppose a complaint causes a seller damage worth *D*, and filing costs the complainer *c*. Then a buyer who has *already received their goods* can go to the seller and say: refund me, or I file anyway. The seller compares losing the refund against suffering *D*, and pays whenever the refund is cheaper.

So the amount extractable by extortion is *D* minus *c*. But *D* is also exactly the deterrent that stops sellers cheating. **Making the mechanism a better deterrent makes it a better extortion tool, one for one.**

In the original design, filing costs nothing and the damage is the whole bond, so the extractable amount is enormous. Worse, the convention that a bond should exceed the order value *guarantees* that paying an extortionist is the rational choice.

You cannot tune your way out of this. The only available levers are: what filing costs the filer, and whether the damage is proportional and reversible rather than catastrophic and permanent.

## Two further defects

**Ammunition is free.** In the sequence above, the claim is handed over *before* the buyer pays. So anyone can open a hundred conversations, collect a hundred signed claims, pay for none of them, and file them all. Destroying a seller costs nothing.

**There is no denominator.** Because success is silent, a record shows "two complaints" but never "two out of five hundred". Every complaint therefore lands at full weight, which is precisely what makes the extortion threat so valuable.

# Part 4 — The reframe: complaints as withdrawals

The repair is to stop treating a complaint as *evidence about someone's character* and start treating it as **a withdrawal from a posted balance**.

## Standing

A seller's **standing** is their cumulative burned capital: the original ghostkey donation, plus any number of top-up donations bound to the same identity. It grows over the identity's life. The money is genuinely gone — donated, not held.

Burning rather than escrowing is not a stylistic choice. Escrow requires a custodian, and there is none. Burning is the only way to make a cost verifiable by strangers with nobody holding anything, and it cannot be quietly withdrawn the night before a scam.

## Complaints spend standing

A filed complaint about an order worth *v* reduces the seller's effective standing by *w × v*, where *w* is a multiplier greater than one. Nothing is seized — the money was already burned. What makes it function like a fine is simply that every buyer's software agrees to subtract it when working out whether a seller is good for an order.

This is *virtual seizure*: the effect of a penalty, with no operator, no arbitration, and no reversibility problem.

## Why the multiplier must exceed one

If a complaint cost exactly what was stolen, the crime would fund itself: steal $50, lose $50 of standing, top up with the stolen $50, break even.

More precisely, deterrence requires the *expected* cost to exceed the take. If only half of defrauded buyers bother to complain, the multiplier must exceed two. In general it must exceed one divided by the complaint rate.

The multiplier is the design's one honest tuning knob, and it trades off visibly: a larger multiplier deters fraud better and simultaneously makes extortion more valuable, exactly as Part 3 predicted.

## What the reframe repairs

**The entry-fee problem disappears.** Standing grows with investment over an identity's life, so an established seller genuinely has more at stake than a newcomer. Replacing a depleted identity costs precisely what it cost to build, so abandoning one buys nothing. Identity churn becomes pointless: a complained-about identity is not tainted, merely poorer.

**The denominator problem dissolves rather than being solved.** Complaints are no longer a rate needing an average. Two complaints against $5,000 of standing reads correctly as minor; the same two against $60 reads correctly as fatal. Nothing needs to know the transaction count.

**Faking a reputation becomes identical to paying.** The only way to raise standing is to burn real money. The signal *is* the cost, so there is nothing to fake.

**The "first complaint is most damaging" cliff inverts.** Marginal damage is the same for everyone, but as a fraction of standing it shrinks as standing grows. The most established sellers become the least extortable — the opposite of the original design.

# Part 5 — A transaction, step by step

Alice sells hot sauce. Bob buys a $50 bottle. Alice's standing is $500. The multiplier is 2.

## Step 0 — Alice sets up shop

**What Alice does.** She donates to Freenet to create an identity, and donates more later as her shop grows. Her interface shows something like: *Your bond: $500. You can carry up to $250 of orders at once.* To take bigger orders she donates more.

**What Bob does.** Nothing; he has not heard of Alice yet.

**Underneath.** Each donation produces a certificate binding the amount to Alice's identity key. The certificates sit in her public record, where anyone can verify them against Freenet's master key.

## Step 1 — Bob decides whether Alice is good for it

**What Bob sees.** Beneath the listing price, a line reading: *Seller has $500 staked, $60 of orders in progress, your $50 order is well covered.* He clicks buy. Nothing else is asked of him.

**What Alice sees.** Nothing. She does not know Bob is looking.

**Underneath.** Bob's software fetches Alice's record, verifies her certificates chain back to the master key, adds up her donations, and subtracts twice any unresolved complaints and twice her open orders. $500 minus $120 leaves $380 of spare capacity; Bob's order needs $100 of it.

**Why it works this way.** Bob is not asking whether Alice seems honest. He is asking whether more money is staked than he is about to risk — a question with an arithmetic answer, requiring nobody's judgement, including his own.

The sum is done by Bob's own software rather than by the network, and that is not an implementation detail. A seller's standing goes down when complaints land, so it is not a stable quantity. A Freenet contract must reach the same verdict on the same data forever, or peers permanently disagree about what is valid and the state never converges. So no contract may depend on a value that moves. Bob's own software has no such obligation and can freely count, weigh and expire things.

This is the first appearance of a principle that recurs throughout: **the network stores facts, and the reader forms the verdict.**

## Step 2 — Alice publicly declares the order

**What Alice sees.** An order appears: *Bob wants one Ghost Pepper, $50. Accept? This will use $100 of your $380 spare capacity.* She clicks accept.

**What Bob sees.** *Waiting for the seller to confirm.*

**Underneath.** Accepting writes an **order commitment** into Alice's public record: a scrambled order number, the amount, and a recent Bitcoin block hash. It reveals nothing about who Bob is or what he bought.

**Why this exists.** This is the anti-scam mechanism. It makes Alice's total exposure countable by strangers. Without it, orders are private and nobody can see how much she currently owes in undelivered goods.

**Why it must come before payment.** If Alice could take money without declaring it, she could quietly run $5,000 of orders against $500 of collateral and vanish. Declaring first caps what she can ever be holding at once. She cannot take money without first admitting, publicly, that she owes goods.

**Why a Bitcoin block hash.** Contracts cannot read a clock — a merge that depends on the current time is not a function of its inputs, so replicas would diverge. Embedding a recent block hash proves the entry is *no earlier than* that block, and the reader's own clock supplies the rest. The asymmetry falls the right way: you cannot make a fresh order look old, because looking old requires having published early, which is exactly the behaviour being forced.

## Step 3 — Bob's software checks the declaration is real

**What Bob sees.** *Confirming… Seller confirmed. Ready to pay.* It takes a few seconds and he does nothing.

**Underneath.** Bob's software reads Alice's record back from the network, confirms his own order is actually present, and re-checks that her total open orders still fit inside her standing.

**Why.** Requiring Bob to see *his own* entry is what forces Alice to publish at all — an undeclared order collects no money. Re-checking the total is what stops Bob being the order that tips her past her collateral.

Note that Bob is not policing the marketplace. He is protecting himself. That is what makes the rule hold without anyone enforcing it: every buyer follows it out of self-interest, and the cap on seller exposure is the collective side effect.

## Step 4 — Alice sends a bill and a pre-signed confession

**What Alice does.** Creates a $50 invoice in her Lightning wallet and pastes it into Harvest.

**What Bob sees.** *Pay $50.* Plus a note: *if this never arrives, you will be able to claim against the seller's bond.*

**Underneath.** Harvest reads the invoice locally and extracts its payment hash and amount, checking they match the order. Alice's software then signs a **claim** — a statement in her own name reading *"I failed to deliver order N, amount $50"* — and sends it privately to Bob along with the invoice.

**Why the seller signs a confession in advance.** There is no oracle for delivery, so no third party can ever attest that Alice failed. The only unforgeable evidence available is a statement Alice wrote herself, beforehand. She cannot dispute it later, because it carries her signature.

**Why it is tied to the invoice.** The confession is useless alone. It becomes usable only together with a secret that the payment network releases when the invoice is paid. So the ability to damage Alice costs exactly $50 — the order value.

**Without that tie,** complaints are free, and the free-ammunition attack from Part 3 returns.

## Step 5 — Bob pays

**What Bob does.** Taps pay, his wallet opens, he confirms.

**What Alice sees.** $50 arriving *in her wallet* — not in Harvest. Harvest does not know yet.

**Underneath.** Settling the payment releases a secret that travels back to Bob's wallet. Harvest checks it matches the invoice and stores it alongside the signed confession. Nothing is published. Bob now holds a complete, usable complaint, and could not have obtained it without paying.

## Step 6 — Alice ships

She posts the bottle. Shipping is entirely invisible to the system, which is the reason the rest of the design is shaped as it is.

## Step 7a — It arrives, and nothing happens at all

**What Bob does.** Enjoys the hot sauce. Nothing else.

**What Alice sees.** After a while, her capacity quietly returns.

**Underneath.** No writes of any kind. The order commitment ages past the complaint window, and readers begin counting it closed.

**Why this matters.** Silence is success. The overwhelmingly common outcome records nothing, which keeps the system small — a busy seller's record grows only when something goes wrong.

"Closed" is a judgement rather than a deletion, because contracts cannot expire anything and records are append-only. Each reader concludes for itself that a commitment is old enough to ignore, using the block anchor. Again: facts on the network, judgement in the reader.

## Step 7b — It never arrives, and Bob complains

**What Bob sees.** *This order is overdue. File a claim? This reduces the seller's bond by $100 and is public — your buyer pseudonym will be attached.* He clicks file.

**What Alice sees.** *A claim was filed. Your bond: $500 to $400. Refund $50 to clear it.*

**Underneath.** Bob publishes Alice's own signed confession together with the payment secret. The network verifies her signature, verifies the secret matches the invoice, and checks the amounts agree. All of it is pure arithmetic — no clock, nothing fetched from elsewhere. Every reader now computes $500 minus $100, leaving $400.

**Why $50 stolen costs $100 of bond.** As Part 4 explained, a penalty equal to the theft would let the crime fund itself.

**Why this is a fine that nobody collects.** The money was burned long ago. What makes it bite is that every buyer's software agrees to subtract it. That is a convention rather than a law — but it holds because each buyer applies it to protect themselves.

## Step 7c — Alice made a mistake and fixes it

**What Alice does.** Pays a refund invoice from her wallet and publishes proof of the refund.

**What Bob sees.** His $50 back, and the claim marked resolved.

**Underneath.** Readers treat the complaint as cured and stop subtracting it. Alice's standing returns to $500.

**Why the cure matters — three reasons.** Honest errors stay survivable, since a lost parcel should not permanently cost a seller twice its value. Complaining becomes worth doing, because Bob files to get his money back rather than merely to punish — which raises the complaint rate, which strengthens the deterrent for everyone. And it caps extortion: a dishonest buyer who received his goods and demands a refund can extract the order value, not the penalty, because refunding is Alice's cheaper option.

**Why even a scammer refunds.** Refunding costs $50; taking the hit costs $100 of bond. Anyone intending to keep selling refunds. Usefully, this means victims who complain tend to get paid by any seller who is not already leaving.

# Part 6 — How this touches the payment network

## Nothing inside Freenet can make a network call

This is absolute. Contracts and delegates are given six capabilities — storage, secrets, logging, randomness, time, and messaging within the node — and nothing else. There is no socket and no HTTP. A delegate could hold a wallet key and sign a transaction, but could never broadcast it.

The web interface cannot either. The gateway runs it in a sandbox permitted to contact only its own origin, so it cannot reach a Lightning node even on the same machine.

## The protocol never needs one

Walk the sequence and ask what genuinely has to cross the boundary. Alice publishes a commitment: pure Freenet. She creates an invoice: her wallet, outside. She signs a confession: pure Freenet. Bob pays: his wallet, outside. **Alice learns she has been paid by looking at her own wallet**, exactly as any merchant with a payment page does. She ships. Bob complains, or does not.

At no point does the protocol require software to *detect* a settlement. The only things crossing are an invoice going out and a short secret coming back — data moving at human speed, not a live connection.

## Why the secret proves payment

Lightning moves money through chains of payment channels. To stop intermediaries stealing funds in transit, each hop is conditional on a secret.

The payee generates a random secret and publishes only its hash in the invoice. Each hop along the route promises: *you get this money if you show something matching that hash.* When the payment reaches the payee, they reveal the secret to claim it, and the secret propagates backwards down the route as each hop collects from the previous one. The payer's wallet ends up holding it.

The payer cannot obtain that secret any other way. It is a random value the payee chose, released only in exchange for being paid. So holding it proves the payment settled — which is why Lightning gives proof of payment where a plain Bitcoin transaction does not.

Harvest's verification is therefore three lines of pure computation: the seller's signature is valid, the secret matches the hash in the confession, and the amounts agree. The platform never learns anything about Lightning; it checks a hash.

## What the buyer's software must check before paying

Three checks, each blocking a real attack. The invoice's payment hash must match the confession's, or the seller could hand over a confession bound to a payment she never intends to settle. The invoice amount must match the confession's, or she could write a $5 confession against a $500 order. And the confession must be signed by the identity whose standing was checked, or the collateral verified is not the collateral at risk.

## Practical routes, and limitations

The workable option today is a payment link plus the clipboard: the interface offers a link that opens the user's wallet, and takes the secret back by paste. A browser wallet extension would make this seamless by paying and returning the secret automatically, though whether extensions can reach Harvest's particular sandbox is untested and worth an early experiment. The fully automatic option would require giving delegates controlled network access, which is a platform change.

Two limits are worth recording. This only works with Lightning: an on-chain Bitcoin payment produces no such secret, so a seller taking on-chain payment cannot produce usable confessions and should be visibly marked as unprotected. And Lightning is slowly migrating to a different conditional-payment scheme for privacy reasons, which would eventually break the hash check and require a different proof.

# Part 7 — Why the platform shapes the design

Several features above look arbitrary until you know what a Freenet contract can and cannot do.

**A contract must be a pure function of its inputs.** Two peers holding the same data must reach the same verdict, forever. Consequently: no reading the clock, no randomness, and no depending on anything that changes.

**Merges must be order-independent and repeat-safe.** Two peers who receive the same updates in different orders must end up identical, and receiving the same update twice must change nothing. Harvest's records satisfy this trivially because they are append-only sets of independently valid facts: merging is a union.

**All contract state is public.** There is no read permission and no authentication.

**Anyone can write.** So spam prevention cannot rely on permission. Harvest handles this by making every write cost real money: raising standing needs a donation, filing a complaint needs a paid order, and a refund proof needs an actual refund. There is no free write anywhere in the design.

**State must stay small**, because reading a record transfers all of it.

The move that makes the whole design possible is to notice that these constraints bind *what the network validates*, not *what software reading the network may conclude*. Keeping the record as an append-only pile of self-proving signed facts, and moving all judgement — counting, weighting, expiry, thresholds — into the reader's own software, dissolves most of the apparent obstacles.

One line must not be crossed. A contract may read another contract's state, but only facts that are immutable or that can only ever become true. Gating validity on something that grows — "reject this if the other party has more than five entries" — flips from valid to invalid over time, so peers validating at different moments disagree permanently. Standing goes down when complaints land, so **no contract may ever gate on standing**. It is computed only by readers.

# Part 8 — What this publishes to the world

The design has a real privacy cost, and it is structural rather than incidental.

Every order produces a public commitment carrying an amount and an approximate timestamp. Over time that is an itemised, timestamped ledger of a seller's business: order values, order frequency, revenue rate, growth, quiet periods, and — because a seller must be online to publish — working hours, from which a time zone can be inferred.

This is more exposed than it sounds. On Freenet, a monitor does not have to scrape anything: any peer hosting the record receives every update pushed to it in real time, for free, undetectably, and with no way for the seller to refuse. Enumerating every seller and subscribing to all of them is a modest project.

Aggregated, that yields the entire economics of the marketplace — total volume, seller count, growth rate, failure rates — continuously, to anyone.

For buyers the picture is uneven, though it is important to be precise about what is exposed. Buying leaks little: a successful order records an amount, with no indication of who bought, and names its listing only as a tag that just the buyer and seller can read. (Orders once named the listing outright, which turned the ledger into a per-product sales record; harvest#57 removed it.) The amount can still give the listing away when it matches a uniquely priced item.

Complaining is different, but what it publishes is a **ghostkey — an anonymous pseudonym, not a person's name**. Nobody learns who the buyer is. What becomes public is that *this pseudonym* transacted with *that seller* for *that amount* on *that date*.

The cost is real but narrower than "your identity is revealed", and it has three parts. First, the pseudonym accumulates a visible complaint history, which is deliberate — it is what limits serial extortion — but it penalises genuine victims for reporting just as much as it penalises abusers, since the record cannot tell them apart. Second, complaints made across different sellers link together under one pseudonym, building a profile of that pseudonym's activity. Third, and only conditionally: pseudonyms can become tied to people through channels outside the system — a delivery address, a payment trail, an operational slip — and if that ever happens, the accumulated history becomes attributable in retrospect.

A buyer can limit all of this by using a separate ghostkey, but each one costs a donation and starts with no history, which is exactly the tension the design creates.

The transparency cannot simply be removed, because it *is* the anti-scam mechanism. The rule that caps a seller's exposure works precisely because every commitment is individually visible and independently countable by every buyer. Publishing only a total instead would let a seller understate it, since each buyer can verify only their own entry. Recovering the privacy would require zero-knowledge proofs — proving that committed orders fit within standing without revealing the components — which is a research-grade addition rather than an adjustment.

One asymmetry is worth noting. Sellers are more exposed to being linked to a person than buyers are: they receive payments that must eventually be cashed out, they ship physical goods, and they run a persistent public storefront. A buyer's ghostkey is far easier to keep isolated. So the same "pseudonym until it isn't" caveat applies to both sides, but it bites harder on the seller.

The honest framing is that this design trades seller business privacy for scam resistance, and the trade is not optional.

# Part 9 — What remains unsolved

**Extortion is bounded, not eliminated.** A buyer who receives goods and demands a refund anyway extracts roughly the order value, once. Their identity accumulates a visible complaint history that limits repetition, but the amount cannot be driven to zero. That follows directly from having no way to distinguish a real victim from a false one.

**Victims of a departing scammer still lose.** The complaint they file destroys collateral the seller had already written off.

**Capacity can be exhausted for free.** Commitments are published before payment and cost the buyer nothing, so an attacker can open orders they never pay for, consume a seller's entire advertised capacity, and leave genuine buyers unable to transact. This is the direct dual of the exit-scam fix: publishing before payment is what stops the seller stealing, and it is what lets a stranger shut them down. Plausible defences all add friction to the buyer side.

**There is a propagation window.** The exposure cap holds once the network has converged. A seller who can serve stale data, or simply race the update, can collect for the duration of that window. This shrinks the exit scam from weeks of demand to minutes of demand; it does not eliminate it.

**The mechanism is a convention, not a law.** Everything depends on buyers' software applying the same scoring rules. It is individually rational to follow them, which is the strongest form of self-enforcement available without an operator, but a population running lax software gets the broken outcomes of Part 3.

**Large one-off trades are out of scope.** An order worth more than any plausible seller's standing cannot be protected this way, and probably cannot be protected by any operator-free reputation mechanism.

**It depends on one payment rail.** Sellers who cannot use Lightning fall back to something close to the broken design.

# Part 10 — The decisions this poses

The two designs are not better and worse versions of one thing; they sit at opposite ends of a single axis.

The original design is **private and small**. Nothing is published, nobody can be profiled, and no seller can ever safely carry more than about a thousand dollars of open orders.

The revised design is **transparent and scalable**. Fraud stops paying at any size and sellers grow by posting capital — but every seller runs a public ledger of their business, and every buyer who complains is named.

Which is right depends on a question that is not technical: what is Harvest for? If it is for trading things people would rather not have permanently recorded, transparency does not trade off against the benefits, it defeats the purpose. If it is for ordinary commerce where a seller would happily publish their volume in exchange for being trusted with larger orders, it is a good bargain.

These could also coexist. A seller might choose to be bonded and public, accepting the ledger in exchange for taking large orders, or to remain unbonded and private, with buyers seeing no history and rationally keeping orders small. The interface would show which, and buyers would price accordingly.

# Appendix — Glossary

**Bond / standing.** The cumulative money a seller has burned by donating to Freenet, bound to their identity. It is the collateral their behaviour is measured against.

**Claim / complaint.** A statement signed by the seller in advance, admitting a specific order was not delivered, held by the buyer and publishable if it is not.

**Contract.** A piece of code on Freenet defining what shared state is valid and how versions merge. Its state is public and it cannot read the clock or make network calls.

**Delegate.** Software running inside a user's own node, holding their secrets and acting on their behalf. It cannot reach the network.

**Ghostkey.** An anonymous identity created by donating to Freenet, whose donation amount is cryptographically attested and unforgeable.

**Order commitment.** A public declaration by a seller that they owe goods for a given amount, published before payment so that total exposure can be counted.

**Multiplier.** The factor by which a complaint reduces standing relative to the order value. Must exceed one, and in practice must exceed one divided by the fraction of victims who complain.

**Preimage.** The secret released by a Lightning payment when it settles, held afterwards by the payer, serving as proof the payment completed.

**Virtual seizure.** The effect of confiscating collateral without anyone confiscating anything, achieved by every participant's software agreeing to discount it.
