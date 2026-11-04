module github.com/sitegoose/sitegoose-go/mongo

go 1.21

require (
	github.com/sitegoose/sitegoose-go v0.3.3
	go.mongodb.org/mongo-driver/v2 v2.0.0
)

// For working on the package; a release drops it.
replace github.com/sitegoose/sitegoose-go => ../
