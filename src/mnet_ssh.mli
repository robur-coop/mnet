type flow

val client :
     Awa.Keys.authenticator
  -> user:string
  -> [ `Pubkey of Awa.Hostkey.priv | `Password of string ]
  -> string
  -> Mnet.TCP.direct Mnet.TCP.flow
  -> (flow, [> `Msg of string ]) result

val read : flow -> bytes -> off:int -> len:int -> int
val write : flow -> string -> off:int -> len:int -> unit
val exit_status : flow -> int option
val close : flow -> unit

module Stop : sig
  type t

  val create : unit -> t
  val switch : t -> unit
end

module type AUTH = sig
  type t

  val verify : t -> string -> Awa.Server.userauth -> bool
end

type t
type db = Database : 'db * (module AUTH with type t = 'db) -> db

type callback = string -> request -> unit

and request =
  | Pty_req of {
        width: int
      ; height: int
      ; max_width: int
      ; max_height: int
      ; term: string
    }
  | Pty_set of {
        width: int
      ; height: int
      ; max_width: int
      ; max_height: int
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

and channel = {
    cmd: string option
  ; id: int
  ; q: string Flux.Bqueue.c
  ; prm: unit Miou.t
}

val server :
     ?stop:Stop.t
  -> db
  -> Awa.Hostkey.priv
  -> Mnet.TCP.direct Mnet.TCP.flow
  -> callback
  -> t
