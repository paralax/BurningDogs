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
    Description : string
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
    let p = new Diagnostics.Process()
    p.StartInfo.FileName <- "/usr/local/bin/yara"
    p.StartInfo.Arguments <- String.Format("-sgm {0} {1}", rulefile, filename)
    p.StartInfo.UseShellExecute <- false
    p.Start() |> ignore
    let output = p.StandardOutput.ReadToEnd().Split([|'\n'|]) // parse
