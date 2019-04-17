open Mirage

let main =
  foreign
    ~packages:[package "duration"]
    "Unikernel.Hello" (time @-> job)

let () =
  register "hello" [main $ default_time]
