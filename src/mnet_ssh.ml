let src = Logs.Src.create "mnet.ssh"

module Log = (val Logs.src_log src : Logs.LOG)
module Q = Flux.Bqueue

module Auth = struct
  type user = {
      name: string
    ; password: string option
    ; keys: Awa.Hostkey.pub list
  }

  type db = user list

  let verify db user userauth =
    match (List.find_opt (fun u -> u.name = user) db, userauth) with
    | None, Awa.Server.Pubkey pkauth ->
        Awa.Server.verify_pubkeyauth ~user pkauth && false
    | (None | Some { password= None; _ }), Awa.Server.Password _ -> false
    | Some u, Awa.Server.Pubkey pkauth ->
        let fn pk = Awa.Hostkey.pub_eq pk pkauth.pubkey in
        Awa.Server.verify_pubkeyauth ~user pkauth && List.exists fn u.keys
    | Some { password= Some password; _ }, Awa.Server.Password password' ->
        let open Digestif.SHA256 in
        let a = digest_string password in
        let b = digest_string password' in
        Digestif.SHA256.equal a b
end

type t = {
    db: Auth.db
  ; cb: callback
  ; channels: channel list
  ; queue: (event, event) Q.t
}

and event =
  [ `Eof
  | `Input of string
  | `Rekey
  | `SSH_out of int32 * string
  | `SSH_err of int32 * string ]

and callback = string -> request -> unit

and request =
  | Pty_req of {
        width: int32
      ; height: int32
      ; max_width: int32
      ; max_height: int32
      ; term: string
    }
  | Pty_set of {
        width: int32
      ; height: int32
      ; max_width: int32
      ; max_height: int32
    }
  | Set_env of { key: string; value: string }
  | Channel of {
        cmd: string
      ; ic: unit -> string option
      ; oc: string -> unit
      ; ec: string -> unit
    }
  | Shell of {
        ic: unit -> string option
      ; oc: string -> unit
      ; ec: string -> unit
    }

and channel = { cmd: string option; id: int32; q: string Q.c; prm: unit Miou.t }

let or_fail ~where = function
  | Ok value -> value
  | Error err -> Fmt.failwith "%s: %s" where err

let now () = Mtime.of_uint64_ns (Int64.of_int (Mkernel.clock_monotonic ()))

let send flow server msg =
  let server, str =
    or_fail ~where:"Mnet_ssh.send" (Awa.Server.output_msg server msg)
  in
  Mnet.TCP.write flow str; server

let sendv flow server msgs =
  let fn = send flow in
  List.fold_left fn server msgs

let lookup t id = List.find_opt (fun c -> id = c.id) t.channels

let username server =
  match server.Awa.Server.auth_state with
  | Awa.Server.Preauth | Awa.Server.Inprogress _ ->
      assert false (* NOTE(dinosaure): I trust @reynir. *)
  | Awa.Server.Done value -> value

let rec nexus t flow (server : string Awa.Server.t) str orphans =
  let where = "Mnet_ssh.nexus" in
  let value = or_fail ~where (Awa.Server.pop_msg2 server str) in
  match value with
  | server, None, str ->
      begin match Miou.care orphans with
      | None | Some None -> nexus t flow server str orphans
      | Some (Some prm) ->
          begin match Miou.await prm with
          | Ok `Rekey ->
              let result = Awa.Server.maybe_rekey server (now ()) in
              let fn (server, msg) = send flow server msg in
              let result = Option.map fn result in
              let server = Option.value ~default:server result in
              nexus t flow server str orphans
          | Ok `Eof ->
              let fn c = Q.close c.q; Miou.cancel c.prm in
              List.iter fn t.channels; t
          | Ok (`Input str') ->
              let _ =
                Miou.async ~orphans @@ fun () ->
                match Mnet.TCP.get flow with
                | Ok sstr -> `Input (String.concat "" sstr)
                | Error (`Eof | `Refused) -> `Eof
              in
              nexus t flow server (str ^ str') orphans
          | Ok (`SSH_out (id, str)) | Ok (`SSH_err (id, str)) ->
              let result = Awa.Server.output_channel_data server id str in
              let server, msgs = or_fail ~where result in
              let server = sendv flow server msgs in
              let _ = Miou.async ~orphans @@ fun () -> Q.get t.queue in
              nexus t flow server str orphans
          | Error exn ->
              Log.err (fun m ->
                  m "Unexpected exception from a task: %s"
                    (Printexc.to_string exn));
              nexus t flow server str orphans
          end
      end
  | server, Some msg, str ->
      let now = now () in
      let result = Awa.Server.input_msg server msg now in
      let server, replies, ev = or_fail ~where result in
      let server = sendv flow server replies in
      begin match ev with
      | None ->
          let _ = Miou.async ~orphans @@ fun () -> Q.get t.queue in
          nexus t flow server str orphans
      | Some (Awa.Server.Userauth (user, userauth)) ->
          let accept = Auth.verify t.db user userauth in
          let result =
            if accept then Awa.Server.accept_userauth server userauth user
            else Awa.Server.reject_userauth server userauth
          in
          let server, reply = or_fail ~where result in
          let server = send flow server reply in
          nexus t flow server str orphans
      | Some (Awa.Server.Pty (term, width, height, max_width, max_height, _)) ->
          let username = username server in
          t.cb username (Pty_req { width; height; max_width; max_height; term });
          nexus t flow server str orphans
      | Some (Awa.Server.Pty_set (width, height, max_width, max_height)) ->
          let username = username server in
          t.cb username (Pty_set { width; height; max_width; max_height });
          nexus t flow server str orphans
      | Some (Awa.Server.Set_env (key, value)) ->
          let username = username server in
          t.cb username (Set_env { key; value });
          nexus t flow server str orphans
      | Some (Awa.Server.Disconnected _) ->
          let fn c = Q.close c.q; Miou.cancel c.prm in
          List.iter fn t.channels; t
      | Some (Awa.Server.Start_shell id) ->
          let q = Q.(create with_close) 0x7ff in
          let ic () = Q.get q in
          let oc str = Q.put t.queue (`SSH_out (id, str)) in
          let ec str = Q.put t.queue (`SSH_err (id, str)) in
          let user = username server in
          let prm = Miou.async @@ fun () -> t.cb user (Shell { ic; oc; ec }) in
          let c = { cmd= None; id; q; prm } in
          let t = { t with channels= c :: t.channels } in
          let _ = Miou.async ~orphans @@ fun () -> Q.get t.queue in
          nexus t flow server str orphans
      | Some (Awa.Server.Channel_eof id) ->
          let fn c = Q.close c.q; Miou.cancel c.prm in
          Option.iter fn (lookup t id);
          (* TODO(dinosaure): on the mirage implementation, we don't recurse and just stop. *)
          nexus t flow server str orphans
      | Some (Awa.Server.Channel_data (id, data)) ->
          let fn c = Q.put c.q data in
          Option.iter fn (lookup t id);
          let _ = Miou.async ~orphans @@ fun () -> Q.get t.queue in
          nexus t flow server str orphans
      | Some (Awa.Server.Channel_subsystem (id, cmd))
      | Some (Awa.Server.Channel_exec (id, cmd)) ->
          let q = Q.(create with_close) 0x7ff in
          let ic () = Q.get q in
          let oc str = Q.put t.queue (`SSH_out (id, str)) in
          let ec str = Q.put t.queue (`SSH_err (id, str)) in
          let user = username server in
          let channel = Channel { cmd; ic; oc; ec } in
          let prm = Miou.async @@ fun () -> t.cb user channel in
          let c = { cmd= Some cmd; id; q; prm } in
          let t = { t with channels= c :: t.channels } in
          let _ = Miou.async ~orphans @@ fun () -> Q.get t.queue in
          nexus t flow server str orphans
      end

module Stop = struct
  type t = {
      mutex: Miou.Mutex.t
    ; condition: Miou.Condition.t
    ; mutable value: bool
  }

  let create () =
    let mutex = Miou.Mutex.create () in
    let condition = Miou.Condition.create () in
    { mutex; condition; value= false }

  let switch t =
    Miou.Mutex.protect t.mutex @@ fun () ->
    t.value <- true;
    Miou.Condition.signal t.condition
end

let server ?stop db priv flow cb =
  let queue = Q.(create infinite) 0x7ff in
  let t = { db; cb; channels= []; queue } in
  let server, msgs = Awa.Server.make priv in
  let server = sendv flow server msgs in
  let orphans = Miou.orphans () in
  let _ =
    Miou.async ~orphans @@ fun () ->
    match Mnet.TCP.get flow with
    | Ok sstr -> `Input (String.concat "" sstr)
    | Error (`Eof | `Refused) -> `Eof
  in
  let fn stop =
    let _ =
      Miou.async ~orphans @@ fun () ->
      Miou.Mutex.protect stop.Stop.mutex @@ fun () ->
      while not stop.value do
        Miou.Condition.wait stop.condition stop.mutex
      done;
      `Eof (* Or [`Stop]? Or [queue] can be [with_close]. *)
    in
    ()
  in
  Option.iter fn stop;
  nexus t flow server "" orphans
