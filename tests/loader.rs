//! End-to-end loader behavior with the bundled fixtures.

use packet_forensics_lab::fixtures;

#[tokio::test]
async fn load_bundled_returns_every_catalog_entry_with_frames() {
    let loaded = packet_forensics_lab::loader::load_bundled().await;
    assert_eq!(loaded.len(), fixtures::all().len());
    for (fixture, result) in &loaded {
        let loaded = result
            .as_ref()
            .unwrap_or_else(|e| panic!("fixture {} failed: {}", fixture.name, e));
        assert!(
            !loaded.frames.is_empty(),
            "fixture {} had no decodable frames",
            fixture.name
        );
        assert!(loaded.report.summary.frames > 0);
    }
}

#[test]
fn every_fixture_file_exists_on_disk() {
    for fixture in fixtures::all() {
        let path = fixtures::path(fixture.filename);
        assert!(path.exists(), "missing fixture file: {}", path.display());
    }
}
