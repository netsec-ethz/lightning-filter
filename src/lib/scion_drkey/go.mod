module example.com/lightning-filter

go 1.16

require (
	github.com/scionproto/scion v0.6.1-0.20220202161514-5883c725f748
	google.golang.org/grpc v1.40.0
)

replace github.com/scionproto/scion => github.com/netsec-ethz/scion v0.6.1-0.20220422080039-25976708fd6b
