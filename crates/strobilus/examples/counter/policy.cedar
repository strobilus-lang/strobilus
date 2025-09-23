@id("P0")
permit (
    principal,
    action,
    resource
)
when {
    principal.counter > 0
};
