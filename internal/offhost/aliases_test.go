package offhost

import (
	"context"

	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// Short names for the types the test doubles' methods take.
type (
	contextType = context.Context
	putOptions  = s3.PutOptions
	objectType  = s3.Object
)
