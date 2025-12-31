package user

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Feature: luo-one-email-manager, Property 1: 用户数据隔离
// For any two different users A and B, user A's data directory path should not overlap
// with user B's data directory path, and user A cannot access user B's data through API.
// Validates: Requirements 1.1, 1.5

func TestProperty_UserDataIsolation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "luo_one_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewManager(tempDir)

	// Property 1.1: Different users have non-overlapping data directories
	properties.Property("different_users_have_non_overlapping_directories", prop.ForAll(
		func(userA, userB uint) bool {
			// Skip if same user
			if userA == userB {
				return true
			}

			dirA, errA := manager.GetUserDataDir(userA)
			dirB, errB := manager.GetUserDataDir(userB)

			if errA != nil || errB != nil {
				return false
			}

			// Directories should be different
			if dirA == dirB {
				return false
			}

			// Neither directory should be a prefix of the other
			absA, _ := filepath.Abs(dirA)
			absB, _ := filepath.Abs(dirB)

			if hasPathPrefix(absA, absB) || hasPathPrefix(absB, absA) {
				return false
			}

			return true
		},
		gen.UIntRange(1, 10000),
		gen.UIntRange(1, 10000),
	))

	// Property 1.2: User cannot access another user's data
	properties.Property("user_cannot_access_other_users_data", prop.ForAll(
		func(requestingUser, targetUser uint) bool {
			err := manager.ValidateUserAccess(requestingUser, targetUser)

			if requestingUser == targetUser {
				// Same user should have access
				return err == nil
			}
			// Different users should be denied
			return err == ErrUserDataAccessDenied
		},
		gen.UIntRange(1, 10000),
		gen.UIntRange(1, 10000),
	))

	// Property 1.3: Path validation prevents cross-user access
	properties.Property("path_validation_prevents_cross_user_access", prop.ForAll(
		func(userA, userB uint) bool {
			if userA == userB || userA == 0 || userB == 0 {
				return true
			}

			// Create directories for both users
			_ = manager.CreateUserDirectories(userA)
			_ = manager.CreateUserDirectories(userB)

			// Get user B's directory
			dirB, err := manager.GetUserDataDir(userB)
			if err != nil {
				return false
			}

			// User A should not be able to validate a path in user B's directory
			err = manager.ValidatePathBelongsToUser(userA, dirB)
			return err == ErrUserDataAccessDenied
		},
		gen.UIntRange(1, 1000),
		gen.UIntRange(1, 1000),
	))

	properties.TestingRun(t)
}


// Property 1.4: User directories are created in isolation
func TestProperty_UserDirectoryCreationIsolation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	properties.Property("user_directories_created_in_isolation", prop.ForAll(
		func(userID uint) bool {
			// Create a fresh temp directory for each test
			tempDir, err := os.MkdirTemp("", "luo_one_isolation_*")
			if err != nil {
				return false
			}
			defer os.RemoveAll(tempDir)

			manager := NewManager(tempDir)

			// Create user directories
			if err := manager.CreateUserDirectories(userID); err != nil {
				return false
			}

			// Verify all expected directories exist
			rawDir, _ := manager.GetRawEmailsDir(userID)
			processedDir, _ := manager.GetProcessedEmailsDir(userID)
			attachDir, _ := manager.GetAttachmentsDir(userID)

			for _, dir := range []string{rawDir, processedDir, attachDir} {
				info, err := os.Stat(dir)
				if err != nil || !info.IsDir() {
					return false
				}
			}

			// Verify directories are under user's base directory
			userDir, _ := manager.GetUserDataDir(userID)
			for _, dir := range []string{rawDir, processedDir, attachDir} {
				if err := manager.ValidatePathBelongsToUser(userID, dir); err != nil {
					return false
				}
				// Also verify the path starts with user directory
				absDir, _ := filepath.Abs(dir)
				absUserDir, _ := filepath.Abs(userDir)
				if !hasPathPrefix(absDir, absUserDir) {
					return false
				}
			}

			return true
		},
		gen.UIntRange(1, 10000),
	))

	properties.TestingRun(t)
}

// Property 1.5: Path traversal attacks are prevented
func TestProperty_PathTraversalPrevention(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 20
	properties := gopter.NewProperties(parameters)

	tempDir, err := os.MkdirTemp("", "luo_one_traversal_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewManager(tempDir)

	properties.Property("path_traversal_attacks_prevented", prop.ForAll(
		func(userID uint) bool {
			if userID == 0 {
				return true
			}

			_ = manager.CreateUserDirectories(userID)

			// Test various path traversal attempts
			maliciousPaths := []string{
				filepath.Join(tempDir, "users", "../../../etc/passwd"),
				filepath.Join(tempDir, "users", ".."),
				"/etc/passwd",
				"../../../etc/passwd",
			}

			for _, path := range maliciousPaths {
				err := manager.ValidatePathBelongsToUser(userID, path)
				if err == nil {
					// Should have been denied
					return false
				}
			}

			return true
		},
		gen.UIntRange(1, 1000),
	))

	properties.TestingRun(t)
}

// hasPathPrefix checks if path has the given prefix
func hasPathPrefix(path, prefix string) bool {
	if len(path) < len(prefix) {
		return false
	}
	if path[:len(prefix)] != prefix {
		return false
	}
	// Ensure it's a proper path prefix (not just string prefix)
	if len(path) > len(prefix) && path[len(prefix)] != filepath.Separator {
		return false
	}
	return true
}
