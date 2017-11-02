open Lwt.Infix

module Hello (Time : Mirage_time_lwt.S) = struct

  let start _time =

    let rec loop = function
      | 0 -> Lwt.return_unit
      | n ->
        Logs.info (fun f -> f "hello");
        Time.sleep_ns (Duration.of_sec 1) >>= fun () ->
        loop (n-1)
    in
    loop 4

end
