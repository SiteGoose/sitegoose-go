module github.com/sitegoose/sitegoose-go/redis

go 1.21

require (
	github.com/redis/go-redis/v9 v9.7.0
	github.com/sitegoose/sitegoose-go v0.4.1
)

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
)

// For working on the package; a release drops it.
replace github.com/sitegoose/sitegoose-go => ../
