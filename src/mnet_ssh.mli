module Stop : sig
  type t

  val create : unit -> t
  val switch : t -> unit
end

module Auth : sig
  type user = {
      name: string
    ; password: string option
    ; keys: Awa.Hostkey.pub list
  }

  type db = user list
end

type t

type callback = string -> request -> unit

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

and channel = {
    cmd: string option
  ; id: int32
  ; q: string Flux.Bqueue.c
  ; prm: unit Miou.t
}

val server :
  ?stop:Stop.t -> Auth.db -> Awa.Hostkey.priv -> Mnet.TCP.flow -> callback -> t
