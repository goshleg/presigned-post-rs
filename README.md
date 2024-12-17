# presigned-post-rs [![Crates.io](https://img.shields.io/crates/v/presigned-post-rs)](https://crates.io/crates/presigned-post-rs)

Simple presigned post for aws s3 api.

### Usage:

```rust
use time::OffsetDateTime;
use presigned_post_rs::PresignedPostData;
use presigned_post_rs::mediatype;

fn main() {
    let presigned_post = PresignedPostData::builder(
        "access_key",
        "key_id",
        "https://storage.yandexcloud.net",
        "ru-central1",
        "test-data",
        "image.png",
    )
    .with_mime(mediatype::media_type!(IMAGE / PNG))
    .with_date(OffsetDateTime::UNIX_EPOCH)
    .with_expiration(time::Duration::minutes(10))
    .with_content_length_range(0, 5 * 1_000_000)
    .build()
    .expect("Failed to build presigned post");
}

```
