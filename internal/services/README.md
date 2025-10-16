# Services

This directory contains microservices that handle specific business logic independently.

## Architecture

Each service follows the microservice pattern:
- **Independent**: Can be modified without affecting other components
- **Standard Interface**: Consistent input/output patterns
- **Testable**: Isolated logic for unit testing
- **Extensible**: Easy to add new services

## Available Services


## Adding New Services

```go
type NewService struct {
    debug bool
}

func (ns *NewService) ProcessData(input string) []Result {
    // Service logic here
    return results
}
```

Register in main.go:
```go
newService := services.NewService(debug)
results := newService.ProcessData(input)
```
