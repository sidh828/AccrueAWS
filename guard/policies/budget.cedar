// Cedar only ever sees one number here: context.cumulative_cost. It has no
// idea a history exists — authorize.py computes that number as
// (everything this session has already spent) + (the request in front of
// it) before Cedar is ever called. See PRIMER.md §1.4-1.5 for why Cedar
// itself can't do that addition.

permit (
    principal,
    action == Action::"transfer",
    resource
);

forbid (
    principal,
    action == Action::"transfer",
    resource
) when {
    context.cumulative_cost > 10000
};
