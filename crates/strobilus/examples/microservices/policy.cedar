permit (
    principal in Group::"secure",
    action,
    resource in Group::"secure"
);

permit (
    principal in Group::"insecure",
    action,
    resource in Group::"insecure"
);

@id("taint")
permit (
    principal in Group::"secure",
    action,
    resource in Group::"insecure"
);
