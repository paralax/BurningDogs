// include Fake lib
#r @"/Users/jose/dotnet/FAKE.3.5.4/tools/FakeLib.dll"
open Fake
open Fake.FscHelper

Target "otx_pulse.exe" (fun _ ->
    ["otx_pulse.fs"]
    |> Fsc (fun p ->
        {p with References = 
            ["packages/Newtonsoft.Json/lib/net40/Newtonsoft.Json.dll"
             ]} 
    ) 
)

Target "hmm_honeypot.exe" (fun _ ->
    ["hmm_honeypot.fs"]
    |> Fsc (fun p -> 
        {p with References = 
            ["packages/Accord/lib/net40/Accord.dll"; 
             "packages/Accord.Statistics/lib/net40/Accord.Statistics.dll";
             "packages/Accord.Math/lib/net40/Accord.Math.dll"
            ]}
    )
)

RunTargetOrDefault "otx_pulse.exe"
