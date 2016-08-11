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

RunTargetOrDefault "otx_pulse.exe"
