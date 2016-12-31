// https://github.com/maliceio/malice-yara

open System
open System.IO
open System.Security.Cryptography
open System.Text

type YaraString = {
    Name : string; 
    Offset : int;
    Data : string
}

type YaraMeta = {
    Description : string;
    Author : string;
    Date : System.DateTime;
    Reference : string;
    Filetype : string;
}

type YaraMatches = {
    Rule : string;
    Namespace : string;
    Tags : string list;
    Meta : YaraMeta;
    Strings : YaraString list;
}

(* 
suspicious_packer_section [packer,PE] [author="@j0sm1",date="2016/10/21",description="The packer/protector section names/keywords",reference="http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/",filetype="binary"] /Users/jose/honeynet/src/third-party/cowrie/dl/66db87ab10f7f6f8e4501d92039438527ced100bd43205b63b572ee51cfece61
0xcb9ea4:$s13: MEW
0x1c4ff0b:$s13: MEW
0x20c3a33:$s13: MEW
0x289510c:$s13: MEW
0x4f6ff86:$s13: MEW
0x624f37a:$s13: MEW
0x637908c:$s13: MEW
0x7102303:$s13: MEW
0x73e2acd:$s13: MEW
0x7c29a47:$s13: MEW
0x1bfea0c:$s61: .yP
0x3ab7ce8:$s61: .yP
0x4912dcb:$s61: .yP
0x4e11b65:$s61: .yP
*)

let yarascan (rulefile: string) (filename: string) : YaraMatches =
    let yaraStrings(input: string []) : YaraString list = 
        let splitLine (line: string) : YaraString =
            let [|offset;name;data|] = line.Split([|':'|])
            {Offset=offset |> int;
            Name=name;
            Data=System.Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes(data.Trim()))}
        input |> Array.map splitLine |> List.ofArray

    let yaraMeta(input: string) : YaraMeta =
        let meta = input.Split(',') 
                |> Array.map (fun x -> x.Split('=')) 
                |> Array.map (fun x -> (x.[0],x.[1].Replace("\"", ""))) 
                |> Map.ofArray
        let getByKey(key: string) (meta : Map<string,string>) : string =
            match Map.tryFind key meta with
            | Some(x) -> x
            | None    -> ""
        let metaDate (date: string) : System.DateTime = 
            match date with 
            | "" -> System.DateTime.UtcNow
            | _  -> System.DateTime.Parse date
        {Description=getByKey "description" meta;
        Author=getByKey "author" meta;
        Date=getByKey "date" meta |> metaDate;
        Reference=getByKey "reference" meta;
        Filetype=getByKey "filetype" meta}

    let p = new Diagnostics.Process()
    p.StartInfo.FileName <- "/usr/local/bin/yara"
    p.StartInfo.Arguments <- String.Format("-sgm {0} {1}", rulefile, filename)
    p.StartInfo.UseShellExecute <- false
    p.Start() |> ignore
    let output = p.StandardOutput.ReadToEnd().Split([|'\n'|]) // parse
    let paren = System.Text.RegularExpressions.Regex("\[[^]]*\]")
    let matches = paren.Matches(output.[0])
    let matchToValue (m : System.Text.RegularExpressions.Match) = m.Value.TrimStart('[').TrimEnd(']')
    let ms = Seq.map matchToValue (Seq.cast matches)
    {Rule=output.[0].Split(' ').[0];
     Namespace="";
     Meta=Seq.skip 1 ms |> Seq.head |> yaraMeta;
     Tags=(Seq.head ms).Split([|','|]) |> List.ofArray;
     Strings=output.[1..] |> yaraStrings}