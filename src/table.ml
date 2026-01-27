module type V = sig
  type t

  val is_disposable : t -> bool
end

module Make (K : Hashtbl.HashedType) (V : V) = struct
  module W = struct
    type t = unit

    let weight () = 1
  end

  module Lru = Lru.M.Make (K) (W)

  type key = K.t
  type value = V.t
  type t = { entries: (key, value) Hashtbl.t; disposables: Lru.t }

  let create size =
    { entries= Hashtbl.create size; disposables= Lru.create size }

  let add t key value =
    Hashtbl.replace t.entries key value;
    if V.is_disposable value then Lru.add key () t.disposables
    else Lru.remove key t.disposables;
    while Lru.weight t.disposables > Lru.capacity t.disposables do
      match Lru.lru t.disposables with
      | None -> ()
      | Some (key', ()) ->
          Hashtbl.remove t.entries key';
          Lru.remove key' t.disposables
    done

  let find t key =
    Lru.promote key t.disposables;
    Hashtbl.find t.entries key

  let remove t key =
    Hashtbl.remove t.entries key;
    Lru.remove key t.disposables

  let fold fn t acc = Hashtbl.fold fn t.entries acc
  let reset t = Hashtbl.reset t.entries
  let iter fn t = Hashtbl.iter fn t.entries
end
