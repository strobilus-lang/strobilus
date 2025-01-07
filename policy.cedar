@pigna_on_true("User--->alice")
@pigna_on_false("User-/->alice")
permit(principal == User::"alice", action == Action::"view", resource );

@pigna_on_true("User--->alice, forbid")
@pigna_on_false("User-/->alice, forbid")
forbid(principal == User::"alice", action == Action::"view", resource );



@pigna_on_true("User--->bob")
@pigna_on_false("User-/->bob")
permit(principal == User::"bob", action == Action::"view", resource);

@pigna_on_true("File 42 is requested")
@pigna_on_false("File 42 is not requested")
permit(principal, action == Action::"view", resource == File::"42");
