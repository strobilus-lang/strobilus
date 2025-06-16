permit (
    principal,
    action == Action::"view",
    resource == File::"42"
)
when {
    principal.counter > 0
};
