use crate::blob::responses::GetBlobResponse;
use crate::blob::{generate_blob_uri, Blob};
use azure_sdk_core::errors::{extract_status_headers_and_body, AzureError, UnexpectedHTTPResult};
use azure_sdk_core::headers::RANGE_GET_CONTENT_MD5;
use azure_sdk_core::lease::LeaseId;
use azure_sdk_core::prelude::*;
use azure_sdk_core::range::Range;
use azure_sdk_core::util::RequestBuilderExt;
use azure_sdk_core::{No, ToAssign, Yes};
use azure_sdk_storage_core::prelude::*;
use chrono::{DateTime, Utc};
use http::request::Builder;
use hyper::{Method, StatusCode};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>
where
    ContainerNameSet: ToAssign,
    BlobNameSet: ToAssign,
    C: Client,
{
    client: &'a C,
    p_container_name: PhantomData<ContainerNameSet>,
    p_blob_name: PhantomData<BlobNameSet>,
    container_name: Option<&'a str>,
    blob_name: Option<&'a str>,
    snapshot: Option<DateTime<Utc>>,
    timeout: Option<u64>,
    range: Option<&'a Range>,
    lease_id: Option<&'a LeaseId>,
    client_request_id: Option<&'a str>,
}

impl<'a, C> GetBlobBuilder<'a, C, No, No>
where
    C: Client,
{
    #[inline]
    pub(crate) fn new(client: &'a C) -> GetBlobBuilder<'a, C, No, No> {
        GetBlobBuilder {
            client,
            p_container_name: PhantomData {},
            container_name: None,
            p_blob_name: PhantomData {},
            blob_name: None,
            snapshot: None,
            timeout: None,
            range: None,
            lease_id: None,
            client_request_id: None,
        }
    }
}

impl<'a, C, ContainerNameSet, BlobNameSet> ClientRequired<'a, C>
    for GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>
where
    ContainerNameSet: ToAssign,
    BlobNameSet: ToAssign,
    C: Client,
{
    #[inline]
    fn client(&self) -> &'a C {
        self.client
    }
}

//get mandatory no traits methods

//set mandatory no traits methods
impl<'a, C, BlobNameSet> ContainerNameRequired<'a> for GetBlobBuilder<'a, C, Yes, BlobNameSet>
where
    BlobNameSet: ToAssign,
    C: Client,
{
    #[inline]
    fn container_name(&self) -> &'a str {
        self.container_name.unwrap()
    }
}

impl<'a, C, ContainerNameSet> BlobNameRequired<'a> for GetBlobBuilder<'a, C, ContainerNameSet, Yes>
where
    ContainerNameSet: ToAssign,
    C: Client,
{
    #[inline]
    fn blob_name(&self) -> &'a str {
        self.blob_name.unwrap()
    }
}

impl<'a, C, ContainerNameSet, BlobNameSet> SnapshotOption
    for GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>
where
    ContainerNameSet: ToAssign,
    BlobNameSet: ToAssign,
    C: Client,
{
    #[inline]
    fn snapshot(&self) -> Option<DateTime<Utc>> {
        self.snapshot
    }
}

impl<'a, C, ContainerNameSet, BlobNameSet> TimeoutOption
    for GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>
where
    ContainerNameSet: ToAssign,
    BlobNameSet: ToAssign,
    C: Client,
{
    #[inline]
    fn timeout(&self) -> Option<u64> {
        self.timeout
    }
}

impl<'a, C, ContainerNameSet, BlobNameSet> RangeOption<'a>
    for GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>
where
    ContainerNameSet: ToAssign,
    BlobNameSet: ToAssign,
    C: Client,
{
    #[inline]
    fn range(&self) -> Option<&'a Range> {
        self.range
    }
}

impl<'a, C, ContainerNameSet, BlobNameSet> LeaseIdOption<'a>
    for GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>
where
    ContainerNameSet: ToAssign,
    BlobNameSet: ToAssign,
    C: Client,
{
    #[inline]
    fn lease_id(&self) -> Option<&'a LeaseId> {
        self.lease_id
    }
}

impl<'a, C, ContainerNameSet, BlobNameSet> ClientRequestIdOption<'a>
    for GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>
where
    ContainerNameSet: ToAssign,
    BlobNameSet: ToAssign,
    C: Client,
{
    #[inline]
    fn client_request_id(&self) -> Option<&'a str> {
        self.client_request_id
    }
}

impl<'a, C, BlobNameSet> ContainerNameSupport<'a> for GetBlobBuilder<'a, C, No, BlobNameSet>
where
    BlobNameSet: ToAssign,
    C: Client,
{
    type O = GetBlobBuilder<'a, C, Yes, BlobNameSet>;

    #[inline]
    fn with_container_name(self, container_name: &'a str) -> Self::O {
        GetBlobBuilder {
            client: self.client,
            p_container_name: PhantomData {},
            p_blob_name: PhantomData {},
            container_name: Some(container_name),
            blob_name: self.blob_name,
            snapshot: self.snapshot,
            timeout: self.timeout,
            range: self.range,
            lease_id: self.lease_id,
            client_request_id: self.client_request_id,
        }
    }
}

impl<'a, C, ContainerNameSet> BlobNameSupport<'a> for GetBlobBuilder<'a, C, ContainerNameSet, No>
where
    ContainerNameSet: ToAssign,
    C: Client,
{
    type O = GetBlobBuilder<'a, C, ContainerNameSet, Yes>;

    #[inline]
    fn with_blob_name(self, blob_name: &'a str) -> Self::O {
        GetBlobBuilder {
            client: self.client,
            p_container_name: PhantomData {},
            p_blob_name: PhantomData {},
            container_name: self.container_name,
            blob_name: Some(blob_name),
            snapshot: self.snapshot,
            timeout: self.timeout,
            range: self.range,
            lease_id: self.lease_id,
            client_request_id: self.client_request_id,
        }
    }
}

impl<'a, C, ContainerNameSet, BlobNameSet> SnapshotSupport
    for GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>
where
    ContainerNameSet: ToAssign,
    BlobNameSet: ToAssign,
    C: Client,
{
    type O = GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>;

    #[inline]
    fn with_snapshot(self, snapshot: DateTime<Utc>) -> Self::O {
        GetBlobBuilder {
            client: self.client,
            p_container_name: PhantomData {},
            p_blob_name: PhantomData {},
            container_name: self.container_name,
            blob_name: self.blob_name,
            snapshot: Some(snapshot),
            timeout: self.timeout,
            range: self.range,
            lease_id: self.lease_id,
            client_request_id: self.client_request_id,
        }
    }
}

impl<'a, C, ContainerNameSet, BlobNameSet> TimeoutSupport
    for GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>
where
    ContainerNameSet: ToAssign,
    BlobNameSet: ToAssign,
    C: Client,
{
    type O = GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>;

    #[inline]
    fn with_timeout(self, timeout: u64) -> Self::O {
        GetBlobBuilder {
            client: self.client,
            p_container_name: PhantomData {},
            p_blob_name: PhantomData {},
            container_name: self.container_name,
            blob_name: self.blob_name,
            snapshot: self.snapshot,
            timeout: Some(timeout),
            range: self.range,
            lease_id: self.lease_id,
            client_request_id: self.client_request_id,
        }
    }
}

impl<'a, C, ContainerNameSet, BlobNameSet> RangeSupport<'a>
    for GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>
where
    ContainerNameSet: ToAssign,
    BlobNameSet: ToAssign,
    C: Client,
{
    type O = GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>;

    #[inline]
    fn with_range(self, range: &'a Range) -> Self::O {
        GetBlobBuilder {
            client: self.client,
            p_container_name: PhantomData {},
            p_blob_name: PhantomData {},
            container_name: self.container_name,
            blob_name: self.blob_name,
            snapshot: self.snapshot,
            timeout: self.timeout,
            range: Some(range),
            lease_id: self.lease_id,
            client_request_id: self.client_request_id,
        }
    }
}

impl<'a, C, ContainerNameSet, BlobNameSet> LeaseIdSupport<'a>
    for GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>
where
    ContainerNameSet: ToAssign,
    BlobNameSet: ToAssign,
    C: Client,
{
    type O = GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>;

    #[inline]
    fn with_lease_id(self, lease_id: &'a LeaseId) -> Self::O {
        GetBlobBuilder {
            client: self.client,
            p_container_name: PhantomData {},
            p_blob_name: PhantomData {},
            container_name: self.container_name,
            blob_name: self.blob_name,
            snapshot: self.snapshot,
            timeout: self.timeout,
            range: self.range,
            lease_id: Some(lease_id),
            client_request_id: self.client_request_id,
        }
    }
}

impl<'a, C, ContainerNameSet, BlobNameSet> ClientRequestIdSupport<'a>
    for GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>
where
    ContainerNameSet: ToAssign,
    BlobNameSet: ToAssign,
    C: Client,
{
    type O = GetBlobBuilder<'a, C, ContainerNameSet, BlobNameSet>;

    #[inline]
    fn with_client_request_id(self, client_request_id: &'a str) -> Self::O {
        GetBlobBuilder {
            client: self.client,
            p_container_name: PhantomData {},
            p_blob_name: PhantomData {},
            container_name: self.container_name,
            blob_name: self.blob_name,
            snapshot: self.snapshot,
            timeout: self.timeout,
            range: self.range,
            lease_id: self.lease_id,
            client_request_id: Some(client_request_id),
        }
    }
}

// methods callable only when every mandatory field has been filled
impl<'a, C> GetBlobBuilder<'a, C, Yes, Yes>
where
    C: Client,
{
    pub async fn finalize(self) -> Result<GetBlobResponse, AzureError> {
        process_request(self).await
    }
}

pub trait Requester {
    type O;
    fn build_request(&self, builder: Builder) -> Builder;
    fn process_response(
        &self,
        status: hyper::StatusCode,
        headers: hyper::HeaderMap,
        body: hyper::body::Bytes,
    ) -> Result<Self::O, AzureError>;
}

async fn process_request<'a, TRequester, C>(s: TRequester) -> Result<TRequester::O, AzureError>
where
    TRequester: Requester
        + SnapshotOption
        + TimeoutOption
        + ClientRequired<'a, C>
        + BlobNameRequired<'a>
        + ContainerNameRequired<'a>,
    C: Client + 'a,
{
    let mut uri = generate_blob_uri(s.client(), s.container_name(), s.blob_name(), None);

    let mut f_first = true;
    if let Some(snapshot) = SnapshotOption::to_uri_parameter(&s) {
        uri = format!("{}?{}", uri, snapshot);
        f_first = false;
    }
    if let Some(timeout) = TimeoutOption::to_uri_parameter(&s) {
        uri = format!("{}{}{}", uri, if f_first { "?" } else { "&" }, timeout);
    }

    trace!("uri == {:?}", uri);

    let future_response = s.client().perform_request(
        &uri,
        &Method::GET,
        &|request| s.build_request(request),
        None,
    )?;

    let (status, headers, body) = extract_status_headers_and_body(future_response).await?;
    s.process_response(status, headers, body)
}

impl<'a, C> Requester for GetBlobBuilder<'a, C, Yes, Yes>
where
    Self: LeaseIdOption<'a>,
    C: Client,
{
    type O = GetBlobResponse;

    fn build_request(&self, mut request: Builder) -> Builder {
        if let Some(r) = self.range() {
            request = LeaseIdOption::add_header(self, request);
            request = RangeOption::add_header(self, request);

            if r.len() <= 4 * 1024 * 1024 {
                request = request.header_static(RANGE_GET_CONTENT_MD5, "true");
            }
        }
        request
    }

    fn process_response(
        &self,
        status: hyper::StatusCode,
        headers: hyper::HeaderMap,
        body: hyper::body::Bytes,
    ) -> Result<GetBlobResponse, AzureError> {
        let expected_status_code = if self.range().is_some() {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        };

        if status != expected_status_code {
            return Err(AzureError::UnexpectedHTTPResult(UnexpectedHTTPResult::new(
                expected_status_code,
                status,
                std::str::from_utf8(&body)?,
            )));
        }

        let container_name = self.container_name();
        let blob_name = self.blob_name();
        let snapshot_time = self.snapshot();

        let blob = Blob::from_headers(&blob_name, &container_name, snapshot_time, &headers)?;
        GetBlobResponse::from_response(&headers, blob, &body)
    }
}

pub struct GetConditionalBlobBuilder<'a, TGetBlobBuilder, TClient> {
    builder: TGetBlobBuilder,
    if_match_condition: IfMatchCondition<'a>,
    _client: PhantomData<&'a TClient>,
}

impl<'a, TClient> IfMatchConditionSupport<'a> for GetBlobBuilder<'a, TClient, Yes, Yes>
where
    TClient: Client,
{
    type O = GetConditionalBlobBuilder<'a, GetBlobBuilder<'a, TClient, Yes, Yes>, TClient>;

    fn with_if_match_condition(self, if_match_condition: IfMatchCondition<'a>) -> Self::O {
        GetConditionalBlobBuilder {
            builder: self,
            if_match_condition,
            _client: PhantomData {},
        }
    }
}

impl<'a, TGetBlobBuilder, TClient> ClientRequired<'a, TClient>
    for GetConditionalBlobBuilder<'a, TGetBlobBuilder, TClient>
where
    TGetBlobBuilder: ClientRequired<'a, TClient>,
    TClient: Client,
{
    fn client(&self) -> &'a TClient {
        self.builder.client()
    }
}

impl<'a, TGetBlobBuilder, TClient> BlobNameRequired<'a>
    for GetConditionalBlobBuilder<'a, TGetBlobBuilder, TClient>
where
    TGetBlobBuilder: BlobNameRequired<'a>,
{
    fn blob_name(&self) -> &'a str {
        self.builder.blob_name()
    }
}

impl<'a, TGetBlobBuilder, TClient> ContainerNameRequired<'a>
    for GetConditionalBlobBuilder<'a, TGetBlobBuilder, TClient>
where
    TGetBlobBuilder: ContainerNameRequired<'a>,
{
    fn container_name(&self) -> &'a str {
        self.builder.container_name()
    }
}

impl<'a, TGetBlobBuilder, TClient> SnapshotOption
    for GetConditionalBlobBuilder<'a, TGetBlobBuilder, TClient>
where
    TGetBlobBuilder: SnapshotOption,
{
    fn snapshot(&self) -> Option<DateTime<Utc>> {
        self.builder.snapshot()
    }
}

impl<'a, TGetBlobBuilder, TClient> TimeoutOption
    for GetConditionalBlobBuilder<'a, TGetBlobBuilder, TClient>
where
    TGetBlobBuilder: TimeoutOption,
{
    fn timeout(&self) -> Option<u64> {
        self.builder.timeout()
    }
}

pub enum ConditionalResult<TResponse> {
    NotModified(),
    Ok(TResponse),
}

impl<'a, TGetBlobBuilder, TClient> Requester
    for GetConditionalBlobBuilder<'a, TGetBlobBuilder, TClient>
where
    TGetBlobBuilder: Requester,
{
    type O = ConditionalResult<TGetBlobBuilder::O>;

    fn build_request(&self, mut builder: Builder) -> Builder {
        builder = self.builder.build_request(builder);
        self.if_match_condition.add_header(builder)
    }

    fn process_response(
        &self,
        status: hyper::StatusCode,
        headers: hyper::HeaderMap,
        body: hyper::body::Bytes,
    ) -> Result<Self::O, AzureError> {
        if status == StatusCode::NOT_MODIFIED {
            return Ok(ConditionalResult::NotModified());
        }

        let result = self.builder.process_response(status, headers, body)?;
        Ok(ConditionalResult::Ok(result))
    }
}

impl<'a, TGetBlobBuilder, TClient> GetConditionalBlobBuilder<'a, TGetBlobBuilder, TClient>
where
    TGetBlobBuilder: Requester
        + SnapshotOption
        + TimeoutOption
        + BlobNameRequired<'a>
        + ContainerNameRequired<'a>
        + ClientRequired<'a, TClient>,
    TClient: Client,
{
    pub async fn finalize(self) -> Result<ConditionalResult<TGetBlobBuilder::O>, AzureError> {
        process_request(self).await
    }
}
