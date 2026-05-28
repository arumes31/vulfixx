1. *Define `AssetWithKeywords` in `internal/models/models.go`*
   - This struct will be used to return assets with their keywords and team names.
2. *Create `internal/db/asset_repo.go`*
   - Implement an `AssetRepository` interface and a concrete implementation `assetRepo`.
   - Implement `ListAssets`, `CreateAsset`, and `DeleteAsset` methods.
   - The `CreateAsset` method will handle the transaction, quota checks, and keyword insertions.
3. *Update `internal/web/app.go`*
   - Add `AssetRepo` field to the `App` struct.
   - Initialize `AssetRepo` in `NewApp`.
4. *Refactor `internal/web/asset_handlers.go`*
   - Split `AssetsHandler` into `listAssetsHandler` and `createAssetHandler` (internal methods called by `AssetsHandler`).
   - Update both to use the new `AssetRepo`.
   - Update `DeleteAssetHandler` to use `AssetRepo`.
5. *Verify the changes*
   - Run `go test ./internal/web/...` to ensure no regressions.
   - Run `go fmt` and `golangci-lint`.
6. *Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.*
7. *Submit the changes.*
