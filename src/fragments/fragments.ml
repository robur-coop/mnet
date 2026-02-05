let src = Logs.Src.create "mnet.fragments"

module Log = (val Logs.src_log src : Logs.LOG)
module SBstr = Slice_bstr

module Make (Key : Hashtbl.HashedType) = struct
  module Value = struct
    type t = { to_expire: int; fragment: Fragment.t; count: int }

    let weight { fragment; _ } = Fragment.weight fragment
  end

  module Cache = Lru.M.Make (Key) (Value)

  type t = { cache: Cache.t; to_expire: int }

  let max_expiration = Int64.to_int (Duration.of_sec 10)

  let create ?(to_expire = max_expiration) () =
    { cache= Cache.create (1024 * 256); to_expire }

  let catch ~on_exn fn = try fn () with exn -> on_exn exn

  type payload = Slice of SBstr.t | String of string

  let insert ~now t key ?(last = false) ~off ~len slice =
    match (off, last, Cache.find key t.cache) with
    | 0, true, None ->
        Log.debug (fun m -> m "receive unfragmented packet");
        Some (key, Slice (SBstr.sub slice ~off:0 ~len))
        (* unfragmented packet *)
    | _, _, None ->
        Log.debug (fun m -> m "receive new fragment");
        (* NOTE(dinosaure): we have an new fragment which is not recorded
           into our cache. We [add] this new fragment and [trim] our
           cache to avoid an OOM. *)
        let fragment = Fragment.singleton ~off ~len ~limit:last slice in
        let to_expire = now + t.to_expire in
        let value = { Value.to_expire; count= 1; fragment } in
        Cache.add key value t.cache;
        Cache.trim t.cache;
        None
    | _, _, Some { count; _ } when count > 16 ->
        Log.debug (fun m -> m "Too many fragments received");
        (* NOTE(dinosaure): from @hannesm, if we have more than 16
           fragments, we just delete our entry from our cache. *)
        Cache.remove key t.cache;
        None
    | _, _, Some { to_expire; _ } when to_expire < now ->
        Log.debug (fun m -> m "Too old fragment");
        (* NOTE(dinosaure): from @hannesm, if we found an entry and get a new
           fragment [max_expiration]ns (10secs), we delete the old entry
           and create a new one. *)
        let fragment = Fragment.singleton ~off ~len ~limit:last slice in
        let to_expire = now + t.to_expire in
        let value = { Value.to_expire; count= 1; fragment } in
        Cache.add key value t.cache;
        None
    | _, _, Some { fragment; count; to_expire } ->
        Log.debug (fun m ->
            m "receive a fragment which completes an existing packet");
        (* NOTE(dinosaure): the basic execution path. If the fragment does not
           fit into our entry, we remove it. Otherwise, we insert the new
           incoming fragment. If the resulted entry is fullfilled, we returns
           the result. Otherwise, we update our cache with our new entry and
           [trim] our cache to avoid an OOM.

           NOTE(dinosaure): [Cache.add] does a promotion of our entry into our
           cache also. *)
        let on_exn _exn = Cache.remove key t.cache; None in
        catch ~on_exn @@ fun () ->
        let str = SBstr.sub_string ~off:0 ~len slice in
        let fragment = Fragment.insert fragment ~off ~limit:last str in
        if Fragment.is_complete fragment then begin
          let str = Fragment.reassemble_exn fragment in
          Cache.remove key t.cache;
          Some (key, String str)
        end
        else begin
          let value = { Value.fragment; count= count + 1; to_expire } in
          Cache.add key value t.cache;
          Cache.trim t.cache;
          None
        end
end
