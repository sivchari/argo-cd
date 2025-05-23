package common

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// Test env var not set for EnvGRPCKeepAliveMin
func Test_GRPCKeepAliveMinNotSet(t *testing.T) {
	grpcKeepAliveMin := GetGRPCKeepAliveEnforcementMinimum()
	grpcKeepAliveExpectedMin := defaultGRPCKeepAliveEnforcementMinimum
	assert.Equal(t, grpcKeepAliveExpectedMin, grpcKeepAliveMin)

	grpcKeepAliveTime := GetGRPCKeepAliveTime()
	assert.Equal(t, 2*grpcKeepAliveExpectedMin, grpcKeepAliveTime)
}

// Test valid env var set for EnvGRPCKeepAliveMin
func Test_GRPCKeepAliveMinIsSet(t *testing.T) {
	numSeconds := 15
	t.Setenv(EnvGRPCKeepAliveMin, fmt.Sprintf("%ds", numSeconds))

	grpcKeepAliveMin := GetGRPCKeepAliveEnforcementMinimum()
	grpcKeepAliveExpectedMin := time.Duration(numSeconds) * time.Second
	assert.Equal(t, grpcKeepAliveExpectedMin, grpcKeepAliveMin)

	grpcKeepAliveTime := GetGRPCKeepAliveTime()
	assert.Equal(t, 2*grpcKeepAliveExpectedMin, grpcKeepAliveTime)
}

// Test invalid env var set for EnvGRPCKeepAliveMin
func Test_GRPCKeepAliveMinIncorrectlySet(t *testing.T) {
	numSeconds := 15
	t.Setenv(EnvGRPCKeepAliveMin, strconv.Itoa(numSeconds))

	grpcKeepAliveMin := GetGRPCKeepAliveEnforcementMinimum()
	grpcKeepAliveExpectedMin := defaultGRPCKeepAliveEnforcementMinimum
	assert.Equal(t, grpcKeepAliveExpectedMin, grpcKeepAliveMin)

	grpcKeepAliveTime := GetGRPCKeepAliveTime()
	assert.Equal(t, 2*grpcKeepAliveExpectedMin, grpcKeepAliveTime)
}

func TestSetOptionalRedisPasswordFromKubeConfig(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name, namespace, expectedPassword, expectedErr string
		secret                                         *corev1.Secret
	}{
		{
			name:             "Secret exists with correct key",
			namespace:        "default",
			expectedPassword: "password123",
			expectedErr:      "",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: RedisInitialCredentials},
				Data:       map[string][]byte{RedisInitialCredentialsKey: []byte("password123")},
			},
		},
		{
			name:             "Secret does not exist",
			namespace:        "default",
			expectedPassword: "",
			expectedErr:      "failed to get secret default/" + RedisInitialCredentials,
			secret:           nil,
		},
		{
			name:             "Secret exists without correct key",
			namespace:        "default",
			expectedPassword: "",
			expectedErr:      fmt.Sprintf("secret default/%s does not contain key %s", RedisInitialCredentials, RedisInitialCredentialsKey),
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: RedisInitialCredentials},
				Data:       map[string][]byte{},
			},
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var (
				ctx          = t.Context()
				kubeClient   = kubefake.NewClientset()
				redisOptions = &redis.Options{}
			)
			if tc.secret != nil {
				_, err := kubeClient.CoreV1().Secrets(tc.namespace).Create(ctx, tc.secret, metav1.CreateOptions{})
				require.NoErrorf(t, err, "Failed to create secret")
			}
			err := SetOptionalRedisPasswordFromKubeConfig(ctx, kubeClient, tc.namespace, redisOptions)
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.expectedPassword, redisOptions.Password)
		})
	}
}
