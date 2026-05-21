module github.com/awslabs/ferret-scan/examples/lambda-redact

go 1.26

require (
	github.com/aws/aws-lambda-go v1.54.0
	github.com/awslabs/ferret-scan v0.0.0-00010101000000-000000000000
)

require (
	github.com/fatih/color v1.19.0 // indirect
	github.com/ledongthuc/pdf v0.0.0-20250511090121-5959a4027728 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/rwcarlsen/goexif v0.0.0-20190401172101-9e8deecbddbd // indirect
	golang.org/x/sys v0.44.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// While this module lives inside the parent repository, point the
// ferret-scan dependency at the local checkout. This keeps the
// submodule buildable from a fresh clone of the monorepo without
// requiring a tagged release of the parent. Consumers who copy this
// directory into their own module should drop the replace directive
// and pin to a real version (go get github.com/awslabs/ferret-scan@latest).
replace github.com/awslabs/ferret-scan => ../..
