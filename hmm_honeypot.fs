(*
    #I "/Users/jose/code/fsharp/ML/Accord.NET-3.3.0/"
#r "Debug/Accord.dll"
#r "Debug/Accord.Statistics.dll"
#r "Debug/Accord.Math.dll"
    *)

// http://accord-framework.net/docs/html/T_Accord_Statistics_Models_Markov_Learning_BaumWelchLearning.htm

open System

open Accord.Math
open Accord.Statistics.Models.Markov.Learning
open Accord.Statistics.Models.Markov

(*
let sequences = [|
    [| 0;5;3;2;5;2|];
    [| 0;5;4;2;5;2|];
    [| 0;5;2;3;5;2|];
    [| 0;5;2;2;5;3|];
    [| 0;1;1;1;1;0;1;1;1;1 |];
    [| 0;1;1;1;0;1;1;1;1;1 |];
    [| 0;1;1;1;1;1;1;1;1;1 |];
    [| 0;1;1;1;1;1 |];
    [| 0;1;1;1;1;1;1 |];
    [| 0;1;1;1;1;1;1;1;1;1 |];
    [| 0;1;1;1;1;1;1;1;1;1 |];
|]

let hmm = new HiddenMarkovModel(7,6)
let teacher = new BaumWelchLearning(hmm)
teacher.Tolerance = 0.0001
teacher.Iterations = 0 
teacher.Learn(sequences)

let l1 = Math.Exp(hmm.LogLikelihood([|0;1|]))
let l2 = Math.Exp(hmm.LogLikelihood([|0;1;1;1|]))
let l3 = Math.Exp(hmm.LogLikelihood([|1;1|]))
let l4 = Math.Exp(hmm.LogLikelihood([|1;0;0;0;|]))
let l5 = Math.Exp(hmm.LogLikelihood([|0; 1; 0; 1; 1; 1; 1; 0; 1 |]))
let l6 = Math.Exp(hmm.LogLikelihood([|0; 1; 1; 1; 1; 1; 1; 1; 1 |]))
*)

(*
    idea
    - train on a batch of honeypot log files, look for the sequence of commands
        - first build a set of commands
        - then turn it into an array
        - for each log file, turn it into a sequence like "[|3;5;10;2;3;2|]" indexed by commands for each session id
        - train an hmm like above on that data set
    - examine new log files
        - for each session id, build a sequence of commands like "[|10;4;1;16;3;2;3|]"
        - hmm.LogLikelihood() that sequence and look for improbable ones
*)

let parse_one(logfile: string) : (string [] * Map<string, string list>) = 
    let getcmd(line: string) : string = 
        // 2017-01-10T21:35:31-0500 [CowrieTelnetTransport,68691,::ffff:39.167.7.160] CMD: sh
        line.Split(' ').[3]
    let getsessionid(line: string) : string = 
        line.Split(' ').[1].Split(',').[1]
    let addcmd(sessionid: string) (cmd: string) (sessions: Map<string,string list>) : Map<string,string list> =
        match Map.containsKey sessionid sessions with
        | true  -> Map.add sessionid (sessions.[sessionid] @ [cmd]) sessions
        | false -> Map.add sessionid [cmd] sessions
    let rec parselines (cmds: Set<string>) (sessions: Map<string, string list>) (lines: string list) = 
        // returns an array of unique commands
        // needs a map of string -> array, where string is the session id and 
        match lines with
        | h::t -> parselines (Set.add (getcmd h) cmds) (addcmd (getsessionid h) (getcmd h) sessions) t
        | []   -> (cmds |> Set.toArray, sessions)
    System.IO.File.ReadAllLines logfile 
    |> Array.toList 
    |> List.filter (fun x -> x.Contains("[CowrieTelnetTransport") && x.Contains("CMD: "))
    |> parselines Set.empty Map.empty

let parse(logfiles: string list): (string [] * int [] []) = 
    // from http://stackoverflow.com/questions/3974758/in-f-how-do-you-merge-2-collections-map-instances
    let join (p:Map<'a,'b>) (q:Map<'a,'b>) = 
        Map(Seq.concat [ (Map.toSeq p) ; (Map.toSeq q) ])
    let results = List.map parse_one logfiles 
    let cmds = results 
               |> List.map fst
               |> Array.concat
               |> Set.ofArray
               |> Set.toArray
    let sessions = results 
                   |> List.map snd
                   |> List.fold join Map.empty<string, string list>                   
    let sequences = Map.toArray sessions 
                    |> Array.map (fun (_, x) -> List.toArray x 
                                                |> Array.map (fun x -> Array.findIndex (fun y -> x = y) cmds ))
    (cmds, sequences)

let train(logfiles: string list) : (string [] * HiddenMarkovModel) = 
    let cmds, sequences = parse logfiles
    let states = Array.max (Array.map (fun x -> Array.length x) sequences)
    let symbols = 1 + (Array.concat sequences |> Array.max)
    let hmm = new HiddenMarkovModel(states, symbols)
    let teacher = new BaumWelchLearning(hmm)
    teacher.Tolerance <- 0.0001
    teacher.Iterations <- 0 
    teacher.Learn(sequences) |> ignore
    (cmds, hmm)

(* now take a logfile and find the interesting sequences 
   yields a map of interesting sessions keyed by session ID -> sequence of commands
*)
let unusual (hmm: HiddenMarkovModel) (cmds: string []) (threshold: float) (logfile: string) : Map<string,string list> = 
    let _, sessions = parse_one logfile
    let tryFindCmd (cmds : string []) (cmd : string) : int = 
        let res = Array.tryFindIndex (fun x -> x = cmd) cmds
        match res with
        | Some i -> i
        | None   -> -1
    let session_to_sequence (cmds: string []) (session: string list) : int [] =
        List.map (fun x -> tryFindCmd cmds x) session |> Array.ofList
    let probability (sequence : int []) : float =
        Math.Exp(hmm.LogLikelihood(sequence))
    Map.map (fun _ v -> (v, probability (session_to_sequence cmds v))) sessions
    |> Map.filter (fun _ (_,p) -> p < threshold)
    |> Map.map (fun _ (v,_) -> v)

[<EntryPoint>]
let main args =
    let cmds, hmm = train (List.ofArray (System.IO.Directory.GetFiles("/Users/jose/honeynet/src/third-party/cowrie/log", "*.log.??")))
    System.IO.Directory.GetFiles("/Users/jose/honeynet/src/third-party/cowrie/log", "*.log.?")
    |> Array.map (fun x -> unusual hmm cmds 0.001 x)
    |> Array.iter (fun x -> printfn "%A" x)
    0