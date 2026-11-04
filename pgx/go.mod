module github.com/sitegoose/sitegoose-go/pgx

go 1.21

require (
	github.com/jackc/pgx/v5 v5.6.0
	github.com/sitegoose/sitegoose-go v0.3.3
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)

// For working on the package; a release drops it.
replace github.com/sitegoose/sitegoose-go => ../
