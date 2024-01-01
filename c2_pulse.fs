open System
open System.IO
open System.Net
open System.Text
open System.Web

open Newtonsoft.Json

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


    p.StartInfo.UseShellExecute <- false
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
    let pulse = apachelogs today
    match List.isEmpty pulse.indicators with
    | true -> ()
    | false -> store today true pulse
    0