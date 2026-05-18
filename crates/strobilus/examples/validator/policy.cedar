@id("P0")
permit (
    principal,
    action == Action::"read",
    resource
)
when {
    principal.counter > 0
};
