@evt("e1")
permit(
    principal,
    action == Action::"view",
    resource == File::"42"
) unless {
    principal.counter <= 0
};

on e1 do { counter:= counter + 1 };
