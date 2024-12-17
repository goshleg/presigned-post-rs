use std::collections::HashMap;

use base64::Engine;
use hmac::digest::InvalidLength;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::macros::format_description;
use time::{Duration, OffsetDateTime};

use crate::impl_debug;

const MEGABYTE_BYTES: u64 = 1_000_000;
const MAX_DEFAULT_SIZE_BYTES: u64 = MEGABYTE_BYTES * 1000; // 1 GB

type HmacSha256 = Hmac<Sha256>;

#[derive(thiserror::Error)]
pub enum Error {
    #[error("Date parsing error: {0}")]
    DateParsingError(#[from] time::error::Format),
    #[error("HMAC signing error: {0}")]
    HmacError(#[from] InvalidLength),
    #[error("JSON serialization error: {0}")]
    JsonSerError(#[from] serde_json::Error),
}

impl_debug!(Error);

#[cfg_attr(feature = "utoipa",
    derive(utoipa::ToSchema, utoipa::ToResponse),
    response(
        description = "Presigned post object data",
        content_type = "application/json",
        example = json!(
            {
                "url": "http://ghashy.garage:9000/mustore-data",
                "fields": {
                "policy": "... long policy ...",
                "key": "abc123-d3090bb8-493b-4837-80fc-cc2deeae3705-image.png",
                "Content-Disposition": "attachment; filename=\"abc123-d3090bb8-493b-4837-80fc-cc2deeae3705-image.png\"",
                "acl": "private",
                "success_action_status": "200",
                "X-Amz-Date": "20240121T211735Z",
                "Content-Type": "image/png",
                "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
                "X-Amz-Signature": "4b08ff30d6f18e95ebe6b797831304c8ab750d7cb98875daeebc2005fb205312",
                "X-Amz-Credential": "garage/20240121/ru-central1/s3/aws4_request"
                }
            }
        )
    ),
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignedPostData {
    pub url: String,
    pub fields: HashMap<String, String>,
}

impl PresignedPostData {
    pub fn builder<'a>(
        access_key: &'a str,
        access_key_id: &'a str,
        obj_storage_endpoint: &'a str,
        region_name: &'a str,
        bucket: &'a str,
        object_key: &'a str,
    ) -> PresignedPostDataBuilder<'a> {
        PresignedPostDataBuilder {
            access_key,
            access_key_id,
            obj_storage_endpoint,
            bucket,
            object_key,
            region_name,
            date: None,
            content_disposition: None,
            expiration: None,
            mime: None,
            service_name: None,
            min_obj_length: None,
            max_obj_length: None,
        }
    }
}

pub struct PresignedPostDataBuilder<'a> {
    access_key: &'a str,
    access_key_id: &'a str,
    obj_storage_endpoint: &'a str,
    bucket: &'a str,
    object_key: &'a str,
    region_name: &'a str,
    date: Option<OffsetDateTime>,
    content_disposition: Option<&'a str>,
    expiration: Option<Duration>,
    mime: Option<mediatype::MediaType<'a>>,
    service_name: Option<&'a str>,
    min_obj_length: Option<u64>,
    max_obj_length: Option<u64>,
}

impl<'a> PresignedPostDataBuilder<'a> {
    pub fn with_date(self, date: OffsetDateTime) -> Self {
        Self {
            date: Some(date),
            ..self
        }
    }

    pub fn with_content_disposition(
        self,
        content_disposition: &'a str,
    ) -> Self {
        Self {
            content_disposition: Some(content_disposition),
            ..self
        }
    }

    pub fn with_expiration(self, expiration: Duration) -> Self {
        Self {
            expiration: Some(expiration),
            ..self
        }
    }

    pub fn with_mime(self, mime: mediatype::MediaType<'a>) -> Self {
        Self {
            mime: Some(mime),
            ..self
        }
    }

    pub fn with_service_name(self, service_name: &'a str) -> Self {
        Self {
            service_name: Some(service_name),
            ..self
        }
    }

    pub fn with_content_length_range(self, min: u64, max: u64) -> Self {
        Self {
            min_obj_length: Some(min),
            max_obj_length: Some(max),
            ..self
        }
    }

    pub fn build(self) -> Result<PresignedPostData, Error> {
        let date = self.date.unwrap_or(OffsetDateTime::now_utc());
        let expiration = date + self.expiration.unwrap_or(Duration::MINUTE);
        let service_name = self.service_name.unwrap_or("s3");
        let mime = self
            .mime
            .unwrap_or(mediatype::media_type!(APPLICATION / OCTET_STREAM));
        let default_disposition =
            format!("attachment; filename=\"{}\"", self.object_key);
        let content_disposition =
            self.content_disposition.unwrap_or(&default_disposition);
        let yyyymmdd_date = get_date_yyyymmdd(date)?;
        let iso8601_date = get_date_iso8601(date)?;
        let x_amz_credential = format!(
            "{}/{}/{}/{}/aws4_request",
            self.access_key_id, yyyymmdd_date, self.region_name, service_name
        );

        let policy = Self::create_policy_document(
            self.bucket,
            self.object_key,
            &mime,
            expiration,
            content_disposition,
            &x_amz_credential,
            &iso8601_date,
            self.min_obj_length.unwrap_or(0),
            self.max_obj_length.unwrap_or(MAX_DEFAULT_SIZE_BYTES),
        )?;

        let signing_key = get_signing_key(
            self.access_key,
            &yyyymmdd_date,
            self.region_name,
            service_name,
        )?;

        let policy_signature = get_policy_signature(&signing_key, &policy)?;

        let mut map: HashMap<String, String> = HashMap::new();
        map.insert("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into());
        map.insert("X-Amz-Date".into(), iso8601_date.into());
        map.insert("success_action_status".into(), "200".into());
        map.insert("X-Amz-Signature".into(), policy_signature.into());
        map.insert("key".into(), self.object_key.into());
        map.insert("bucket".into(), self.bucket.to_owned());
        // NOTE: Garage doesn't support S3 ACL access control mechanisms, uses its own system instead, built around a per-access-key-per-bucket logic
        // map.insert("acl".into(), "private".into());
        map.insert("policy".into(), policy.into());
        map.insert("X-Amz-Credential".into(), x_amz_credential.into());
        map.insert("Content-Type".into(), mime.to_string());
        map.insert(
            "Content-Disposition".into(),
            content_disposition.to_string(),
        );

        Ok(PresignedPostData {
            url: format!("{}/{}", self.obj_storage_endpoint, self.bucket),
            fields: map,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn create_policy_document(
        bucket: &str,
        object_key: &str,
        mime: &mediatype::MediaType<'_>,
        expiration: OffsetDateTime,
        content_disposition: &str,
        x_amz_credential: &str,
        iso8601_date: &str,
        min: u64,
        max: u64,
    ) -> Result<String, Error> {
        let policy = serde_json::json!({
            "expiration": expiration.format(&time::format_description::well_known::Rfc3339).map_err(Error::DateParsingError)?,
            "conditions": [
                {"X-Amz-Algorithm": "AWS4-HMAC-SHA256"},
                {"X-Amz-Date": iso8601_date},
                {"X-Amz-Credential": x_amz_credential},
                {"bucket": bucket},
                {"key": object_key},
                // NOTE: Garage doesn't support S3 ACL access control mechanisms, uses its own system instead, built around a per-access-key-per-bucket logic
                // {"acl": "private"},
                {"success_action_status": "200"},
                {"Content-Disposition": content_disposition},
                ["starts-with", "$Content-Type", mime.ty.as_ref()],
                ["content-length-range", min, max]
            ]
        });
        let policy =
            serde_json::to_string(&policy).map_err(Error::JsonSerError)?;
        // Base64 encode the policy document
        Ok(base64::engine::general_purpose::STANDARD.encode(policy))
    }
}

fn get_date_yyyymmdd(date: OffsetDateTime) -> Result<String, Error> {
    let yyyymmdd_format = format_description!("[year][month][day]");
    let yyyymmdd_date = date
        .format(&yyyymmdd_format)
        .map_err(Error::DateParsingError)?;
    Ok(yyyymmdd_date)
}

fn get_date_iso8601(date: OffsetDateTime) -> Result<String, Error> {
    let iso8601_format =
        format_description!("[year][month][day]T[hour][minute][second]Z");
    let iso8601_date = date
        .format(&iso8601_format)
        .map_err(Error::DateParsingError)?;
    Ok(iso8601_date)
}

fn sign(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(Error::HmacError)?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn get_signing_key(
    access_key: &str,
    date: &str,
    region_name: &str,
    service_name: &str,
) -> Result<Vec<u8>, Error> {
    let k_date =
        sign(format!("AWS4{}", access_key).as_bytes(), date.as_bytes())?;
    let k_region = sign(&k_date, region_name.as_bytes())?;
    let k_service = sign(&k_region, service_name.as_bytes())?;
    sign(&k_service, b"aws4_request")
}

fn get_policy_signature(
    signing_key: &[u8],
    policy_document_base64: &str,
) -> Result<String, Error> {
    // Sign the policy document
    let signature = sign(signing_key, policy_document_base64.as_bytes())?;
    Ok(hex::encode(signature))
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use crate::ppo::MEGABYTE_BYTES;

    use super::PresignedPostData;

    #[test]
    fn data_form_correct_from_template() {
        let key_id = "test_key_id";
        let access_key = "test_access_id";

        let presigned_post = PresignedPostData::builder(
            access_key,
            key_id,
            "https://storage.yandexcloud.net",
            "ru-central1",
            "test-data",
            "image.png",
        )
        .with_mime(mediatype::media_type!(IMAGE / PNG))
        .with_date(OffsetDateTime::UNIX_EPOCH)
        .with_expiration(time::Duration::minutes(10))
        .with_content_length_range(0, 5 * MEGABYTE_BYTES)
        .build()
        .expect("Failed to build presigned post form");

        assert_eq!(
            presigned_post.url,
            "https://storage.yandexcloud.net/test-data"
        );
        assert_eq!(
            presigned_post
                .fields
                .get("X-Amz-Algorithm")
                .map(|alg| alg.as_str()),
            Some("AWS4-HMAC-SHA256")
        );
        assert_eq!(
            presigned_post
                .fields
                .get("X-Amz-Credential")
                .map(|cred| cred.as_str()),
            Some("test_key_id/19700101/ru-central1/s3/aws4_request")
        );
        assert_eq!(
            presigned_post
                .fields
                .get("success_action_status")
                .map(|s| s.as_str()),
            Some("200")
        );
        assert_eq!(
            presigned_post
                .fields
                .get("X-Amz-Date")
                .map(|date| date.as_str()),
            Some("19700101T000000Z")
        );
        assert_eq!(
            presigned_post.fields.get("key").map(|key| key.as_str()),
            Some("image.png")
        );
        assert_eq!(
            presigned_post
                .fields
                .get("Content-Type")
                .map(|t| t.as_str()),
            Some("image/png")
        );
        // NOTE: Garage doesn't support S3 ACL access control mechanisms, uses its own system instead, built around a per-access-key-per-bucket logic
        // assert_eq!(
        //     presigned_post.fields.get("acl").map(|acl| acl.as_str()),
        //     Some("private")
        // );
        assert_eq!(
            presigned_post.fields.get("policy").map(|p| p.as_str()),
            Some("eyJjb25kaXRpb25zIjpbeyJYLUFtei1BbGdvcml0aG0iOiJBV1M0LUhNQUMtU0hBMjU2In0seyJYLUFtei1EYXRlIjoiMTk3MDAxMDFUMDAwMDAwWiJ9LHsiWC1BbXotQ3JlZGVudGlhbCI6InRlc3Rfa2V5X2lkLzE5NzAwMTAxL3J1LWNlbnRyYWwxL3MzL2F3czRfcmVxdWVzdCJ9LHsiYnVja2V0IjoidGVzdC1kYXRhIn0seyJrZXkiOiJpbWFnZS5wbmcifSx7InN1Y2Nlc3NfYWN0aW9uX3N0YXR1cyI6IjIwMCJ9LHsiQ29udGVudC1EaXNwb3NpdGlvbiI6ImF0dGFjaG1lbnQ7IGZpbGVuYW1lPVwiaW1hZ2UucG5nXCIifSxbInN0YXJ0cy13aXRoIiwiJENvbnRlbnQtVHlwZSIsImltYWdlIl0sWyJjb250ZW50LWxlbmd0aC1yYW5nZSIsMCw1MDAwMDAwMDAwMDAwXV0sImV4cGlyYXRpb24iOiIxOTcwLTAxLTAxVDAwOjEwOjAwWiJ9")
        );
        assert_eq!(
            presigned_post.fields.get("X-Amz-Signature").map(|s| s.as_str()),
            Some("731a9fb7beb797517bc6336c4a956e06daeb6dc6c1ddee3e64909e01212b0dba")
        );
        assert_eq!(
            presigned_post
                .fields
                .get("Content-Disposition")
                .map(|s| s.as_str()),
            Some("attachment; filename=\"image.png\"")
        );
    }
}
