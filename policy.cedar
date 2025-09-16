permit (
    principal,
    action == Action::"get",
    resource == Resource::"thesis.tex"
)
when {
    principal.counter > 0
};
