open System
open System.IO
open System.Text

open Newtonsoft.Json

open Log

type OtxIndicator = {
     Type : string;
     indicator : string;
     description : string;
     role : string
}

type OtxPulse = {
     name : string;
     description : string;
     Public : bool;
     TLP : string;
     indicators : OtxIndicator list;
     tags : string list;
     references : string list;
     attack_ids : string list
}

(*
{
  "timestamp": "2022-04-14T03:50:56+00:00",
  "action": "authenticate",
  "REMOTE_ADDR": "46.246.122.77",
  "username": "destinee46",
  "password": "Idell2013!",
  "passwordText": "",
  "HTTP_USER_AGENT": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/99.0.4844.59 Mobile/15E148 Safari/604.1"
}
*)

type OwapotEvent = {
    timestamp : string;
    action : string;
    REMOTE_ADDR : string;
    username : string;
    password : string;
    p.Start() |> ignore
    p.StandardOutput.ReadToEnd() |> ignore
    ()

let store (date:DateTime) (doSymlink: bool) (otx: OtxPulse) =
    let json = JsonConvert.SerializeObject(otx).Replace("Type", "type").Replace("Public", "public")
    let today = date.ToString("yyyyMMdd")
    let dir = createDir("/Library/WebServer/Documents/data/" + otx.name.Split(' ').[0])
    let filename = dir.FullName + "/" + today + ".txt"
    File.WriteAllText(filename, json)
    match doSymlink with
    | true -> symlink (FileInfo(filename).Name) (dir.FullName + "/" + "latest.txt")
    | _    -> ()

[<EntryPoint>]
let main args =
    let today = DateTime.Today
    [ owalogs; ]
    |> List.map (fun fn -> fn today)
    |> List.filter (fun x -> not (List.isEmpty (x.indicators)))
    |> List.map (fun x -> store today true x)
    |> ignore
    0