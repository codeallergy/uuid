# uuid

Golang UUID implementation that supports TimeUUID version

### Quick start example:
```
	uuid := uuid.New(uuid.TimebasedVer1)
	uuid.SetUnixTimeMillis(123)
	uuid.SetCounter(555)
	fmt.Print(uuid.MarshalBinary())
	uuid.Parse(uuid.String())
```
