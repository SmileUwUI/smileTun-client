build:
	go build -o bin/main cmd/main.go

run:
	go run main.go


compile:
	GOOS=linux GOARCH=amd64 go build -o bin/main-linux-amd64 cmd/main.go
	GOOS=linux GOARCH=386 go build -o bin/main-linux-386 cmd/main.go
	
	GOOS=linux GOARCH=arm64 go build -o bin/main-linux-arm64 cmd/main.go
	GOOS=linux GOARCH=arm GOARM=7 go build -o bin/main-linux-armv7 cmd/main.go
	